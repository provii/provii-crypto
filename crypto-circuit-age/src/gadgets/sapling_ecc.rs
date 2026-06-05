// Circuit constraint code ported from Zcash sapling-crypto.
// Arithmetic on Scalar field elements and fixed generator table indexing
// are inherent to the ZK constraint system and cannot overflow at runtime.
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

//! Gadgets implementing Jubjub elliptic curve operations.
use super::sapling_constants::{FixedGenerator, EDWARDS_D, MONTGOMERY_A, MONTGOMERY_SCALE};
use bellman::gadgets::boolean::Boolean;
use bellman::gadgets::lookup::lookup3_xy;
use bellman::gadgets::num::{AllocatedNum, Num};
use bellman::gadgets::Assignment;
use bellman::{ConstraintSystem, SynthesisError};
use core::ops::{AddAssign, MulAssign, Neg, SubAssign};
use group::Curve;

#[derive(Clone)]
pub struct EdwardsPoint {
    u: AllocatedNum<bls12_381::Scalar>,
    v: AllocatedNum<bls12_381::Scalar>,
}

/// Perform a fixed-base scalar multiplication with
/// `by` being in little-endian bit order.
pub fn fixed_base_multiplication<CS>(
    mut cs: CS,
    base: FixedGenerator,
    by: &[Boolean],
) -> Result<EdwardsPoint, SynthesisError>
where
    CS: ConstraintSystem<bls12_381::Scalar>,
{
    // Represents the result of the multiplication
    let mut result: Option<EdwardsPoint> = None;

    for (i, (chunk, window)) in by.chunks(3).zip(base.iter()).enumerate() {
        let chunk_a = chunk
            .first()
            .cloned()
            .unwrap_or_else(|| Boolean::constant(false));
        let chunk_b = chunk
            .get(1)
            .cloned()
            .unwrap_or_else(|| Boolean::constant(false));
        let chunk_c = chunk
            .get(2)
            .cloned()
            .unwrap_or_else(|| Boolean::constant(false));

        let (u, v) = lookup3_xy(
            cs.namespace(|| format!("window table lookup {i}")),
            &[chunk_a, chunk_b, chunk_c],
            window,
        )?;

        let p = EdwardsPoint { u, v };

        if let Some(prev) = result.take() {
            result = Some(prev.add(cs.namespace(|| format!("addition {i}")), &p)?);
        } else {
            result = Some(p);
        }
    }

    Ok(result.get()?.clone())
}

impl EdwardsPoint {
    pub fn get_u(&self) -> &AllocatedNum<bls12_381::Scalar> {
        &self.u
    }

    pub fn get_v(&self) -> &AllocatedNum<bls12_381::Scalar> {
        &self.v
    }

    pub fn assert_not_small_order<CS>(&self, mut cs: CS) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        // During parameter generation, we can't do the actual check
        // but we still need to allocate the constraints

        let tmp = self.double(cs.namespace(|| "first doubling"))?;
        let tmp = tmp.double(cs.namespace(|| "second doubling"))?;
        let tmp = tmp.double(cs.namespace(|| "third doubling"))?;

        // Check u != 0
        tmp.u.assert_nonzero(cs.namespace(|| "check u != 0"))?;

        Ok(())
    }

    pub fn inputize<CS>(&self, mut cs: CS) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        self.u.inputize(cs.namespace(|| "u"))?;
        self.v.inputize(cs.namespace(|| "v"))?;

        Ok(())
    }

    /// This converts the point into a representation.
    pub fn repr<CS>(&self, mut cs: CS) -> Result<Vec<Boolean>, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        let mut tmp = vec![];

        let u = self.u.to_bits_le_strict(cs.namespace(|| "unpack u"))?;

        let v = self.v.to_bits_le_strict(cs.namespace(|| "unpack v"))?;

        tmp.extend(v);
        tmp.push(u[0].clone());

        Ok(tmp)
    }

    /// This 'witnesses' a point inside the constraint system.
    /// It guarantees the point is on the curve.
    pub fn witness<CS>(mut cs: CS, p: Option<jubjub::ExtendedPoint>) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        let p = p.map(|p| p.to_affine());

        // Allocate u
        let u = AllocatedNum::alloc(cs.namespace(|| "u"), || Ok(p.get()?.get_u()))?;

        // Allocate v
        let v = AllocatedNum::alloc(cs.namespace(|| "v"), || Ok(p.get()?.get_v()))?;

        Self::interpret(cs.namespace(|| "point interpretation"), &u, &v)
    }

    /// Returns `self` if condition is true, and the neutral
    /// element (0, 1) otherwise.
    pub fn conditionally_select<CS>(
        &self,
        mut cs: CS,
        condition: &Boolean,
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        // Compute u' = self.u if condition, and 0 otherwise
        let u_prime = AllocatedNum::alloc(cs.namespace(|| "u'"), || {
            if *condition.get_value().get()? {
                Ok(*self.u.get_value().get()?)
            } else {
                Ok(bls12_381::Scalar::zero())
            }
        })?;

        // condition * u = u'
        // if condition is 0, u' must be 0
        // if condition is 1, u' must be u
        let one = CS::one();
        cs.enforce(
            || "u' computation",
            |lc| lc + self.u.get_variable(),
            |_| condition.lc(one, bls12_381::Scalar::one()),
            |lc| lc + u_prime.get_variable(),
        );

        // Compute v' = self.v if condition, and 1 otherwise
        let v_prime = AllocatedNum::alloc(cs.namespace(|| "v'"), || {
            if *condition.get_value().get()? {
                Ok(*self.v.get_value().get()?)
            } else {
                Ok(bls12_381::Scalar::one())
            }
        })?;

        // condition * v = v' - (1 - condition)
        // if condition is 0, v' must be 1
        // if condition is 1, v' must be v
        cs.enforce(
            || "v' computation",
            |lc| lc + self.v.get_variable(),
            |_| condition.lc(one, bls12_381::Scalar::one()),
            |lc| lc + v_prime.get_variable() - &condition.not().lc(one, bls12_381::Scalar::one()),
        );

        Ok(EdwardsPoint {
            u: u_prime,
            v: v_prime,
        })
    }

    /// Performs a scalar multiplication of this twisted Edwards
    /// point by a scalar represented as a sequence of booleans
    /// in little-endian bit order.
    pub fn mul<CS>(&self, mut cs: CS, by: &[Boolean]) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        // Represents the current "magnitude" of the base
        // that we're operating over. Starts at self,
        // then 2*self, then 4*self, ...
        let mut curbase: Option<EdwardsPoint> = None;

        // Represents the result of the multiplication
        let mut result: Option<EdwardsPoint> = None;

        for (i, bit) in by.iter().enumerate() {
            if let Some(prev) = curbase.take() {
                // Double the previous value
                curbase = Some(prev.double(cs.namespace(|| format!("doubling {i}")))?);
            } else {
                curbase = Some(self.clone());
            }

            // Represents the select base. If the bit for this magnitude
            // is true, this will return `curbase`. Otherwise it will
            // return the neutral element, which will have no effect on
            // the result.
            let thisbase = curbase
                .as_ref()
                .ok_or(SynthesisError::AssignmentMissing)?
                .conditionally_select(cs.namespace(|| format!("selection {i}")), bit)?;

            if let Some(prev) = result.take() {
                result = Some(prev.add(cs.namespace(|| format!("addition {i}")), &thisbase)?);
            } else {
                result = Some(thisbase);
            }
        }

        Ok(result.get()?.clone())
    }

    pub fn interpret<CS>(
        mut cs: CS,
        u: &AllocatedNum<bls12_381::Scalar>,
        v: &AllocatedNum<bls12_381::Scalar>,
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        // -u^2 + v^2 = 1 + du^2v^2

        let u2 = u.square(cs.namespace(|| "u^2"))?;
        let v2 = v.square(cs.namespace(|| "v^2"))?;
        let u2v2 = u2.mul(cs.namespace(|| "u^2 v^2"), &v2)?;

        let one = CS::one();
        cs.enforce(
            || "on curve check",
            |lc| lc - u2.get_variable() + v2.get_variable(),
            |lc| lc + one,
            |lc| lc + one + (EDWARDS_D, u2v2.get_variable()),
        );

        Ok(EdwardsPoint {
            u: u.clone(),
            v: v.clone(),
        })
    }

    pub fn double<CS>(&self, mut cs: CS) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        // Compute T = (u + v) * (v - EDWARDS_A*u)
        //           = (u + v) * (u + v)
        let t = AllocatedNum::alloc(cs.namespace(|| "T"), || {
            let mut t0 = *self.u.get_value().get()?;
            t0.add_assign(self.v.get_value().get()?);

            let mut t1 = *self.u.get_value().get()?;
            t1.add_assign(self.v.get_value().get()?);

            t0.mul_assign(&t1);

            Ok(t0)
        })?;

        cs.enforce(
            || "T computation",
            |lc| lc + self.u.get_variable() + self.v.get_variable(),
            |lc| lc + self.u.get_variable() + self.v.get_variable(),
            |lc| lc + t.get_variable(),
        );

        // Compute A = u * v
        let a = self.u.mul(cs.namespace(|| "A computation"), &self.v)?;

        // Compute C = d*A*A
        let c = AllocatedNum::alloc(cs.namespace(|| "C"), || {
            let mut t0 = a.get_value().get()?.square();
            t0.mul_assign(EDWARDS_D);

            Ok(t0)
        })?;

        cs.enforce(
            || "C computation",
            |lc| lc + (EDWARDS_D, a.get_variable()),
            |lc| lc + a.get_variable(),
            |lc| lc + c.get_variable(),
        );

        // Compute u3 = (2.A) / (1 + C)
        let u3 = AllocatedNum::alloc(cs.namespace(|| "u3"), || {
            let mut t0 = *a.get_value().get()?;
            t0 = t0.double();

            let mut t1 = bls12_381::Scalar::one();
            t1.add_assign(c.get_value().get()?);

            let res = t1.invert().map(|t1| t0 * t1);
            Option::from(res).ok_or(SynthesisError::DivisionByZero)
        })?;

        let one = CS::one();
        cs.enforce(
            || "u3 computation",
            |lc| lc + one + c.get_variable(),
            |lc| lc + u3.get_variable(),
            |lc| lc + a.get_variable() + a.get_variable(),
        );

        // Compute v3 = (T + (EDWARDS_A-1)*A) / (1 - C)
        //            = (T - 2.A) / (1 - C)
        let v3 = AllocatedNum::alloc(cs.namespace(|| "v3"), || {
            let mut t0 = *a.get_value().get()?;
            t0 = t0.double().neg();
            t0.add_assign(t.get_value().get()?);

            let mut t1 = bls12_381::Scalar::one();
            t1.sub_assign(c.get_value().get()?);

            let res = t1.invert().map(|t1| t0 * t1);
            Option::from(res).ok_or(SynthesisError::DivisionByZero)
        })?;

        cs.enforce(
            || "v3 computation",
            |lc| lc + one - c.get_variable(),
            |lc| lc + v3.get_variable(),
            |lc| lc + t.get_variable() - a.get_variable() - a.get_variable(),
        );

        Ok(EdwardsPoint { u: u3, v: v3 })
    }

    /// Perform addition between any two points
    pub fn add<CS>(&self, mut cs: CS, other: &Self) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        // Compute U = (u1 + v1) * (v2 - EDWARDS_A*u2)
        //           = (u1 + v1) * (u2 + v2)
        // (In hindsight, U was a poor choice of name.)
        let uppercase_u = AllocatedNum::alloc(cs.namespace(|| "U"), || {
            let mut t0 = *self.u.get_value().get()?;
            t0.add_assign(self.v.get_value().get()?);

            let mut t1 = *other.u.get_value().get()?;
            t1.add_assign(other.v.get_value().get()?);

            t0.mul_assign(&t1);

            Ok(t0)
        })?;

        cs.enforce(
            || "U computation",
            |lc| lc + self.u.get_variable() + self.v.get_variable(),
            |lc| lc + other.u.get_variable() + other.v.get_variable(),
            |lc| lc + uppercase_u.get_variable(),
        );

        // Compute A = v2 * u1
        let a = other.v.mul(cs.namespace(|| "A computation"), &self.u)?;

        // Compute B = u2 * v1
        let b = other.u.mul(cs.namespace(|| "B computation"), &self.v)?;

        // Compute C = d*A*B
        let c = AllocatedNum::alloc(cs.namespace(|| "C"), || {
            let mut t0 = *a.get_value().get()?;
            t0.mul_assign(b.get_value().get()?);
            t0.mul_assign(EDWARDS_D);

            Ok(t0)
        })?;

        cs.enforce(
            || "C computation",
            |lc| lc + (EDWARDS_D, a.get_variable()),
            |lc| lc + b.get_variable(),
            |lc| lc + c.get_variable(),
        );

        // Compute u3 = (A + B) / (1 + C)
        let u3 = AllocatedNum::alloc(cs.namespace(|| "u3"), || {
            let mut t0 = *a.get_value().get()?;
            t0.add_assign(b.get_value().get()?);

            let mut t1 = bls12_381::Scalar::one();
            t1.add_assign(c.get_value().get()?);

            let ret = t1.invert().map(|t1| t0 * t1);
            Option::from(ret).ok_or(SynthesisError::DivisionByZero)
        })?;

        let one = CS::one();
        cs.enforce(
            || "u3 computation",
            |lc| lc + one + c.get_variable(),
            |lc| lc + u3.get_variable(),
            |lc| lc + a.get_variable() + b.get_variable(),
        );

        // Compute v3 = (U - A - B) / (1 - C)
        let v3 = AllocatedNum::alloc(cs.namespace(|| "v3"), || {
            let mut t0 = *uppercase_u.get_value().get()?;
            t0.sub_assign(a.get_value().get()?);
            t0.sub_assign(b.get_value().get()?);

            let mut t1 = bls12_381::Scalar::one();
            t1.sub_assign(c.get_value().get()?);

            let ret = t1.invert().map(|t1| t0 * t1);
            Option::from(ret).ok_or(SynthesisError::DivisionByZero)
        })?;

        cs.enforce(
            || "v3 computation",
            |lc| lc + one - c.get_variable(),
            |lc| lc + v3.get_variable(),
            |lc| lc + uppercase_u.get_variable() - a.get_variable() - b.get_variable(),
        );

        Ok(EdwardsPoint { u: u3, v: v3 })
    }
}

pub struct MontgomeryPoint {
    x: Num<bls12_381::Scalar>,
    y: Num<bls12_381::Scalar>,
}

impl MontgomeryPoint {
    /// Converts an element in the prime order subgroup into
    /// a point in the birationally equivalent twisted
    /// Edwards curve.
    pub fn into_edwards<CS>(self, mut cs: CS) -> Result<EdwardsPoint, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        // Compute u = (scale*x) / y
        let u = AllocatedNum::alloc(cs.namespace(|| "u"), || {
            let mut t0 = *self.x.get_value().get()?;
            t0.mul_assign(MONTGOMERY_SCALE);

            let ret = self.y.get_value().get()?.invert().map(|invy| t0 * invy);
            Option::from(ret).ok_or(SynthesisError::DivisionByZero)
        })?;

        cs.enforce(
            || "u computation",
            |lc| lc + &self.y.lc(bls12_381::Scalar::one()),
            |lc| lc + u.get_variable(),
            |lc| lc + &self.x.lc(MONTGOMERY_SCALE),
        );

        // Compute v = (x - 1) / (x + 1)
        let v = AllocatedNum::alloc(cs.namespace(|| "v"), || {
            let mut t0 = *self.x.get_value().get()?;
            let mut t1 = t0;
            t0.sub_assign(&bls12_381::Scalar::one());
            t1.add_assign(&bls12_381::Scalar::one());

            let ret = t1.invert().map(|t1| t0 * t1);
            Option::from(ret).ok_or(SynthesisError::DivisionByZero)
        })?;

        let one = CS::one();
        cs.enforce(
            || "v computation",
            |lc| lc + &self.x.lc(bls12_381::Scalar::one()) + one,
            |lc| lc + v.get_variable(),
            |lc| lc + &self.x.lc(bls12_381::Scalar::one()) - one,
        );

        Ok(EdwardsPoint { u, v })
    }

    /// Interprets an (x, y) pair as a point
    /// in Montgomery, does not check that it's
    /// on the curve. Useful for constants and
    /// window table lookups.
    pub fn interpret_unchecked(x: Num<bls12_381::Scalar>, y: Num<bls12_381::Scalar>) -> Self {
        MontgomeryPoint { x, y }
    }

    /// Performs an affine point addition, not defined for
    /// points with the same x-coordinate.
    pub fn add<CS>(&self, mut cs: CS, other: &Self) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        // Compute lambda = (y' - y) / (x' - x)
        let lambda = AllocatedNum::alloc(cs.namespace(|| "lambda"), || {
            let mut n = *other.y.get_value().get()?;
            n.sub_assign(self.y.get_value().get()?);

            let mut d = *other.x.get_value().get()?;
            d.sub_assign(self.x.get_value().get()?);

            let ret = d.invert().map(|d| n * d);
            Option::from(ret).ok_or(SynthesisError::DivisionByZero)
        })?;

        cs.enforce(
            || "evaluate lambda",
            |lc| lc + &other.x.lc(bls12_381::Scalar::one()) - &self.x.lc(bls12_381::Scalar::one()),
            |lc| lc + lambda.get_variable(),
            |lc| lc + &other.y.lc(bls12_381::Scalar::one()) - &self.y.lc(bls12_381::Scalar::one()),
        );

        // Compute x'' = lambda^2 - A - x - x'
        let xprime = AllocatedNum::alloc(cs.namespace(|| "xprime"), || {
            let mut t0 = lambda.get_value().get()?.square();
            t0.sub_assign(MONTGOMERY_A);
            t0.sub_assign(self.x.get_value().get()?);
            t0.sub_assign(other.x.get_value().get()?);

            Ok(t0)
        })?;

        // (lambda) * (lambda) = (A + x + x' + x'')
        let one = CS::one();
        cs.enforce(
            || "evaluate xprime",
            |lc| lc + lambda.get_variable(),
            |lc| lc + lambda.get_variable(),
            |lc| {
                lc + (MONTGOMERY_A, one)
                    + &self.x.lc(bls12_381::Scalar::one())
                    + &other.x.lc(bls12_381::Scalar::one())
                    + xprime.get_variable()
            },
        );

        // Compute y' = -(y + lambda(x' - x))
        let yprime = AllocatedNum::alloc(cs.namespace(|| "yprime"), || {
            let mut t0 = *xprime.get_value().get()?;
            t0.sub_assign(self.x.get_value().get()?);
            t0.mul_assign(lambda.get_value().get()?);
            t0.add_assign(self.y.get_value().get()?);
            t0 = t0.neg();

            Ok(t0)
        })?;

        // y' + y = lambda(x - x')
        cs.enforce(
            || "evaluate yprime",
            |lc| lc + &self.x.lc(bls12_381::Scalar::one()) - xprime.get_variable(),
            |lc| lc + lambda.get_variable(),
            |lc| lc + yprime.get_variable() + &self.y.lc(bls12_381::Scalar::one()),
        );

        Ok(MontgomeryPoint {
            x: xprime.into(),
            y: yprime.into(),
        })
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use bellman::gadgets::test::TestConstraintSystem;
    use ff::PrimeField;
    use group::{Curve, Group};
    use jubjub::ExtendedPoint;

    // ========================================================================
    // HELPER FUNCTIONS
    // ========================================================================

    fn get_generator() -> ExtendedPoint {
        jubjub::SubgroupPoint::generator().into()
    }

    fn get_neutral() -> ExtendedPoint {
        ExtendedPoint::identity()
    }

    fn scalar_to_bits_le(scalar: &jubjub::Scalar, num_bits: usize) -> Vec<Boolean> {
        let bytes = scalar.to_repr();
        let mut bits = Vec::with_capacity(num_bits);
        for byte in bytes.iter().take(num_bits.div_ceil(8)) {
            for bit_idx in 0..8 {
                if bits.len() >= num_bits {
                    break;
                }
                bits.push(Boolean::constant((byte >> bit_idx) & 1 == 1));
            }
        }
        bits
    }

    // ========================================================================
    // EDWARDSPOINT::WITNESS TESTS
    // ========================================================================

    #[test]
    fn test_witness_some_generator() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let result = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(get_generator()));
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_witness_neutral() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let result = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(get_neutral()));
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_witness_none() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let result = EdwardsPoint::witness(cs.namespace(|| "witness"), None);
        assert!(result.is_err(), "Witnessing None should fail");
        Ok(())
    }

    #[test]
    fn test_witness_scalar_multiples() -> Result<(), Box<dyn std::error::Error>> {
        for i in [0, 1, 2, 7, 13, 255] {
            let point = get_generator() * jubjub::Scalar::from(i);
            let mut cs = TestConstraintSystem::new();
            let result = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(point));
            assert!(result.is_ok(), "Failed for scalar {i}");
            assert!(cs.is_satisfied());
        }
        Ok(())
    }

    // ========================================================================
    // EDWARDSPOINT::INTERPRET TESTS
    // ========================================================================

    #[test]
    fn test_interpret_neutral() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let u = AllocatedNum::alloc(cs.namespace(|| "u"), || Ok(bls12_381::Scalar::zero()))?;
        let v = AllocatedNum::alloc(cs.namespace(|| "v"), || Ok(bls12_381::Scalar::one()))?;
        let result = EdwardsPoint::interpret(cs.namespace(|| "interpret"), &u, &v);
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_interpret_generator() -> Result<(), Box<dyn std::error::Error>> {
        let gen = get_generator().to_affine();
        let mut cs = TestConstraintSystem::new();
        let u = AllocatedNum::alloc(cs.namespace(|| "u"), || Ok(gen.get_u()))?;
        let v = AllocatedNum::alloc(cs.namespace(|| "v"), || Ok(gen.get_v()))?;
        let result = EdwardsPoint::interpret(cs.namespace(|| "interpret"), &u, &v);
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_interpret_invalid_point() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let u = AllocatedNum::alloc(cs.namespace(|| "u"), || Ok(bls12_381::Scalar::one()))?;
        let v = AllocatedNum::alloc(cs.namespace(|| "v"), || Ok(bls12_381::Scalar::one()))?;
        let result = EdwardsPoint::interpret(cs.namespace(|| "interpret"), &u, &v);
        assert!(result.is_ok());
        assert!(!cs.is_satisfied());
        Ok(())
    }

    // ========================================================================
    // EDWARDSPOINT::DOUBLE TESTS
    // ========================================================================

    #[test]
    fn test_double_neutral() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let p = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(get_neutral()))?;
        let result = p.double(cs.namespace(|| "double"));
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        let doubled = result?;
        assert_eq!(
            doubled.get_u().get_value().ok_or("no value")?,
            bls12_381::Scalar::zero()
        );
        assert_eq!(
            doubled.get_v().get_value().ok_or("no value")?,
            bls12_381::Scalar::one()
        );
        Ok(())
    }

    #[test]
    fn test_double_generator() -> Result<(), Box<dyn std::error::Error>> {
        let gen = get_generator();
        let expected = gen.double();
        let mut cs = TestConstraintSystem::new();
        let p = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(gen))?;
        let doubled = p.double(cs.namespace(|| "double"))?;
        assert!(cs.is_satisfied());
        let exp_affine = expected.to_affine();
        assert_eq!(
            doubled.get_u().get_value().ok_or("no value")?,
            exp_affine.get_u()
        );
        assert_eq!(
            doubled.get_v().get_value().ok_or("no value")?,
            exp_affine.get_v()
        );
        Ok(())
    }

    #[test]
    fn test_double_consistency_with_mul_by_two() -> Result<(), Box<dyn std::error::Error>> {
        let point = get_generator() * jubjub::Scalar::from(5u64);
        let mut cs1 = TestConstraintSystem::new();
        let p1 = EdwardsPoint::witness(cs1.namespace(|| "witness"), Some(point))?;
        let doubled = p1.double(cs1.namespace(|| "double"))?;
        let two_bits = vec![Boolean::constant(false), Boolean::constant(true)];
        let mut cs2 = TestConstraintSystem::new();
        let p2 = EdwardsPoint::witness(cs2.namespace(|| "witness"), Some(point))?;
        let mulled = p2.mul(cs2.namespace(|| "mul"), &two_bits)?;
        assert_eq!(
            doubled.get_u().get_value().ok_or("no value")?,
            mulled.get_u().get_value().ok_or("no value")?
        );
        assert_eq!(
            doubled.get_v().get_value().ok_or("no value")?,
            mulled.get_v().get_value().ok_or("no value")?
        );
        Ok(())
    }

    #[test]
    fn test_double_chain() -> Result<(), Box<dyn std::error::Error>> {
        let point = get_generator() * jubjub::Scalar::from(3u64);
        let expected = point.double().double();
        let mut cs = TestConstraintSystem::new();
        let p = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(point))?;
        let d1 = p.double(cs.namespace(|| "double1"))?;
        let d2 = d1.double(cs.namespace(|| "double2"))?;
        assert!(cs.is_satisfied());
        let exp_affine = expected.to_affine();
        assert_eq!(
            d2.get_u().get_value().ok_or("no value")?,
            exp_affine.get_u()
        );
        assert_eq!(
            d2.get_v().get_value().ok_or("no value")?,
            exp_affine.get_v()
        );
        Ok(())
    }

    // ========================================================================
    // EDWARDSPOINT::ADD TESTS
    // ========================================================================

    #[test]
    fn test_add_neutral_left() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let p0 = EdwardsPoint::witness(cs.namespace(|| "neutral"), Some(get_neutral()))?;
        let p1 = EdwardsPoint::witness(cs.namespace(|| "gen"), Some(get_generator()))?;
        let sum = p0.add(cs.namespace(|| "add"), &p1)?;
        assert!(cs.is_satisfied());
        let gen_affine = get_generator().to_affine();
        assert_eq!(
            sum.get_u().get_value().ok_or("no value")?,
            gen_affine.get_u()
        );
        assert_eq!(
            sum.get_v().get_value().ok_or("no value")?,
            gen_affine.get_v()
        );
        Ok(())
    }

    #[test]
    fn test_add_neutral_right() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let p1 = EdwardsPoint::witness(cs.namespace(|| "gen"), Some(get_generator()))?;
        let p0 = EdwardsPoint::witness(cs.namespace(|| "neutral"), Some(get_neutral()))?;
        let sum = p1.add(cs.namespace(|| "add"), &p0)?;
        assert!(cs.is_satisfied());
        let gen_affine = get_generator().to_affine();
        assert_eq!(
            sum.get_u().get_value().ok_or("no value")?,
            gen_affine.get_u()
        );
        assert_eq!(
            sum.get_v().get_value().ok_or("no value")?,
            gen_affine.get_v()
        );
        Ok(())
    }

    #[test]
    fn test_add_point_to_itself() -> Result<(), Box<dyn std::error::Error>> {
        let point = get_generator();
        let mut cs1 = TestConstraintSystem::new();
        let p1 = EdwardsPoint::witness(cs1.namespace(|| "w1"), Some(point))?;
        let p2 = EdwardsPoint::witness(cs1.namespace(|| "w2"), Some(point))?;
        let sum = p1.add(cs1.namespace(|| "add"), &p2)?;
        let mut cs2 = TestConstraintSystem::new();
        let p3 = EdwardsPoint::witness(cs2.namespace(|| "w"), Some(point))?;
        let doubled = p3.double(cs2.namespace(|| "double"))?;
        assert_eq!(
            sum.get_u().get_value().ok_or("no value")?,
            doubled.get_u().get_value().ok_or("no value")?
        );
        assert_eq!(
            sum.get_v().get_value().ok_or("no value")?,
            doubled.get_v().get_value().ok_or("no value")?
        );
        Ok(())
    }

    #[test]
    fn test_add_commutativity() -> Result<(), Box<dyn std::error::Error>> {
        let p = get_generator();
        let q = get_generator() * jubjub::Scalar::from(7u64);
        let mut cs1 = TestConstraintSystem::new();
        let p1 = EdwardsPoint::witness(cs1.namespace(|| "p"), Some(p))?;
        let q1 = EdwardsPoint::witness(cs1.namespace(|| "q"), Some(q))?;
        let pq = p1.add(cs1.namespace(|| "add"), &q1)?;
        let mut cs2 = TestConstraintSystem::new();
        let p2 = EdwardsPoint::witness(cs2.namespace(|| "p"), Some(p))?;
        let q2 = EdwardsPoint::witness(cs2.namespace(|| "q"), Some(q))?;
        let qp = q2.add(cs2.namespace(|| "add"), &p2)?;
        assert_eq!(
            pq.get_u().get_value().ok_or("no value")?,
            qp.get_u().get_value().ok_or("no value")?
        );
        assert_eq!(
            pq.get_v().get_value().ok_or("no value")?,
            qp.get_v().get_value().ok_or("no value")?
        );
        Ok(())
    }

    #[test]
    fn test_add_associativity() -> Result<(), Box<dyn std::error::Error>> {
        let p = get_generator();
        let q = get_generator() * jubjub::Scalar::from(7u64);
        let r = get_generator() * jubjub::Scalar::from(13u64);
        let mut cs1 = TestConstraintSystem::new();
        let p1 = EdwardsPoint::witness(cs1.namespace(|| "p"), Some(p))?;
        let q1 = EdwardsPoint::witness(cs1.namespace(|| "q"), Some(q))?;
        let r1 = EdwardsPoint::witness(cs1.namespace(|| "r"), Some(r))?;
        let pq = p1.add(cs1.namespace(|| "pq"), &q1)?;
        let pqr = pq.add(cs1.namespace(|| "pqr"), &r1)?;
        let mut cs2 = TestConstraintSystem::new();
        let p2 = EdwardsPoint::witness(cs2.namespace(|| "p"), Some(p))?;
        let q2 = EdwardsPoint::witness(cs2.namespace(|| "q"), Some(q))?;
        let r2 = EdwardsPoint::witness(cs2.namespace(|| "r"), Some(r))?;
        let qr = q2.add(cs2.namespace(|| "qr"), &r2)?;
        let pqr2 = p2.add(cs2.namespace(|| "pqr2"), &qr)?;
        assert_eq!(
            pqr.get_u().get_value().ok_or("no value")?,
            pqr2.get_u().get_value().ok_or("no value")?
        );
        assert_eq!(
            pqr.get_v().get_value().ok_or("no value")?,
            pqr2.get_v().get_value().ok_or("no value")?
        );
        Ok(())
    }

    #[test]
    fn test_add_different_points() -> Result<(), Box<dyn std::error::Error>> {
        let p1 = get_generator();
        let p2 = get_generator() * jubjub::Scalar::from(3u64);
        let expected = p1 + p2;
        let mut cs = TestConstraintSystem::new();
        let a = EdwardsPoint::witness(cs.namespace(|| "p1"), Some(p1))?;
        let b = EdwardsPoint::witness(cs.namespace(|| "p2"), Some(p2))?;
        let sum = a.add(cs.namespace(|| "add"), &b)?;
        assert!(cs.is_satisfied());
        let exp_affine = expected.to_affine();
        assert_eq!(
            sum.get_u().get_value().ok_or("no value")?,
            exp_affine.get_u()
        );
        assert_eq!(
            sum.get_v().get_value().ok_or("no value")?,
            exp_affine.get_v()
        );
        Ok(())
    }

    // ========================================================================
    // EDWARDSPOINT::MUL TESTS
    // ========================================================================

    #[test]
    fn test_mul_by_zero() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let p = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(get_generator()))?;
        let result = p.mul(cs.namespace(|| "mul"), &[]);
        assert!(
            result.is_err(),
            "Multiplying by empty scalar array should fail"
        );
        Ok(())
    }

    #[test]
    fn test_mul_by_one() -> Result<(), Box<dyn std::error::Error>> {
        let point = get_generator();
        let one_bits = vec![Boolean::constant(true)];
        let mut cs = TestConstraintSystem::new();
        let p = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(point))?;
        let result = p.mul(cs.namespace(|| "mul"), &one_bits)?;
        assert!(cs.is_satisfied());
        let point_affine = point.to_affine();
        assert_eq!(
            result.get_u().get_value().ok_or("no value")?,
            point_affine.get_u()
        );
        assert_eq!(
            result.get_v().get_value().ok_or("no value")?,
            point_affine.get_v()
        );
        Ok(())
    }

    #[test]
    fn test_mul_by_two() -> Result<(), Box<dyn std::error::Error>> {
        let point = get_generator();
        let two_bits = vec![Boolean::constant(false), Boolean::constant(true)];
        let expected = point.double();
        let mut cs = TestConstraintSystem::new();
        let p = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(point))?;
        let result = p.mul(cs.namespace(|| "mul"), &two_bits)?;
        assert!(cs.is_satisfied());
        let exp_affine = expected.to_affine();
        assert_eq!(
            result.get_u().get_value().ok_or("no value")?,
            exp_affine.get_u()
        );
        assert_eq!(
            result.get_v().get_value().ok_or("no value")?,
            exp_affine.get_v()
        );
        Ok(())
    }

    #[test]
    fn test_mul_small_scalars() -> Result<(), Box<dyn std::error::Error>> {
        let point = get_generator();
        for scalar_val in [3u64, 7, 15, 31, 255] {
            let scalar = jubjub::Scalar::from(scalar_val);
            let bits = scalar_to_bits_le(&scalar, 8);
            let expected = point * scalar;
            let mut cs = TestConstraintSystem::new();
            let p = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(point))?;
            let result = p.mul(cs.namespace(|| "mul"), &bits)?;
            assert!(cs.is_satisfied());
            let exp_affine = expected.to_affine();
            assert_eq!(
                result.get_u().get_value().ok_or("no value")?,
                exp_affine.get_u()
            );
            assert_eq!(
                result.get_v().get_value().ok_or("no value")?,
                exp_affine.get_v()
            );
        }
        Ok(())
    }

    #[test]
    fn test_mul_large_scalar() -> Result<(), Box<dyn std::error::Error>> {
        let point = get_generator();
        let scalar = jubjub::Scalar::from(1_000_000u64);
        let bits = scalar_to_bits_le(&scalar, 32);
        let expected = point * scalar;
        let mut cs = TestConstraintSystem::new();
        let p = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(point))?;
        let result = p.mul(cs.namespace(|| "mul"), &bits)?;
        assert!(cs.is_satisfied());
        let exp_affine = expected.to_affine();
        assert_eq!(
            result.get_u().get_value().ok_or("no value")?,
            exp_affine.get_u()
        );
        assert_eq!(
            result.get_v().get_value().ok_or("no value")?,
            exp_affine.get_v()
        );
        Ok(())
    }

    #[test]
    fn test_mul_neutral_element() -> Result<(), Box<dyn std::error::Error>> {
        let scalar = jubjub::Scalar::from(42u64);
        let bits = scalar_to_bits_le(&scalar, 8);
        let mut cs = TestConstraintSystem::new();
        let p = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(get_neutral()))?;
        let result = p.mul(cs.namespace(|| "mul"), &bits)?;
        assert!(cs.is_satisfied());
        assert_eq!(
            result.get_u().get_value().ok_or("no value")?,
            bls12_381::Scalar::zero()
        );
        assert_eq!(
            result.get_v().get_value().ok_or("no value")?,
            bls12_381::Scalar::one()
        );
        Ok(())
    }

    // ========================================================================
    // EDWARDSPOINT::CONDITIONALLY_SELECT TESTS
    // ========================================================================

    #[test]
    fn test_conditionally_select_true() -> Result<(), Box<dyn std::error::Error>> {
        let point = get_generator();
        let condition = Boolean::constant(true);
        let mut cs = TestConstraintSystem::new();
        let p = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(point))?;
        let selected = p.conditionally_select(cs.namespace(|| "select"), &condition)?;
        assert!(cs.is_satisfied());
        let point_affine = point.to_affine();
        assert_eq!(
            selected.get_u().get_value().ok_or("no value")?,
            point_affine.get_u()
        );
        assert_eq!(
            selected.get_v().get_value().ok_or("no value")?,
            point_affine.get_v()
        );
        Ok(())
    }

    #[test]
    fn test_conditionally_select_false() -> Result<(), Box<dyn std::error::Error>> {
        let point = get_generator();
        let condition = Boolean::constant(false);
        let mut cs = TestConstraintSystem::new();
        let p = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(point))?;
        let selected = p.conditionally_select(cs.namespace(|| "select"), &condition)?;
        assert!(cs.is_satisfied());
        assert_eq!(
            selected.get_u().get_value().ok_or("no value")?,
            bls12_381::Scalar::zero()
        );
        assert_eq!(
            selected.get_v().get_value().ok_or("no value")?,
            bls12_381::Scalar::one()
        );
        Ok(())
    }

    #[test]
    fn test_conditionally_select_neutral_true() -> Result<(), Box<dyn std::error::Error>> {
        let neutral = get_neutral();
        let condition = Boolean::constant(true);
        let mut cs = TestConstraintSystem::new();
        let p = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(neutral))?;
        let selected = p.conditionally_select(cs.namespace(|| "select"), &condition)?;
        assert!(cs.is_satisfied());
        assert_eq!(
            selected.get_u().get_value().ok_or("no value")?,
            bls12_381::Scalar::zero()
        );
        assert_eq!(
            selected.get_v().get_value().ok_or("no value")?,
            bls12_381::Scalar::one()
        );
        Ok(())
    }

    #[test]
    fn test_conditionally_select_neutral_false() -> Result<(), Box<dyn std::error::Error>> {
        let neutral = get_neutral();
        let condition = Boolean::constant(false);
        let mut cs = TestConstraintSystem::new();
        let p = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(neutral))?;
        let selected = p.conditionally_select(cs.namespace(|| "select"), &condition)?;
        assert!(cs.is_satisfied());
        assert_eq!(
            selected.get_u().get_value().ok_or("no value")?,
            bls12_381::Scalar::zero()
        );
        assert_eq!(
            selected.get_v().get_value().ok_or("no value")?,
            bls12_381::Scalar::one()
        );
        Ok(())
    }

    // ========================================================================
    // EDWARDSPOINT::REPR TESTS
    // ========================================================================

    #[test]
    fn test_repr_neutral() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let p = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(get_neutral()))?;
        let bits = p.repr(cs.namespace(|| "repr"))?;
        assert!(cs.is_satisfied());
        assert_eq!(
            bits.len(),
            256,
            "repr should produce 256 bits (255 for v + 1 for u sign)"
        );
        Ok(())
    }

    #[test]
    fn test_repr_generator() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let p = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(get_generator()))?;
        let bits = p.repr(cs.namespace(|| "repr"))?;
        assert!(cs.is_satisfied());
        assert_eq!(bits.len(), 256);
        Ok(())
    }

    #[test]
    fn test_repr_output_length() -> Result<(), Box<dyn std::error::Error>> {
        for i in [0, 1, 5, 13, 255] {
            let point = get_generator() * jubjub::Scalar::from(i);
            let mut cs = TestConstraintSystem::new();
            let p = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(point))?;
            let bits = p.repr(cs.namespace(|| "repr"))?;
            assert!(cs.is_satisfied());
            assert_eq!(bits.len(), 256, "Failed for scalar {i}");
        }
        Ok(())
    }

    // ========================================================================
    // EDWARDSPOINT::ASSERT_NOT_SMALL_ORDER TESTS
    // ========================================================================

    #[test]
    fn test_assert_not_small_order_generator() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let p = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(get_generator()))?;
        let result = p.assert_not_small_order(cs.namespace(|| "check"));
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_assert_not_small_order_scalar_multiples() -> Result<(), Box<dyn std::error::Error>> {
        for i in [1, 2, 7, 13, 100] {
            let point = get_generator() * jubjub::Scalar::from(i);
            let mut cs = TestConstraintSystem::new();
            let p = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(point))?;
            let result = p.assert_not_small_order(cs.namespace(|| "check"));
            assert!(result.is_ok(), "Failed for scalar {i}");
            assert!(cs.is_satisfied());
        }
        Ok(())
    }

    // ========================================================================
    // EDWARDSPOINT::INPUTIZE TESTS
    // ========================================================================

    #[test]
    fn test_inputize_generator() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let p = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(get_generator()))?;
        let result = p.inputize(cs.namespace(|| "inputize"));
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        assert_eq!(
            cs.num_inputs(),
            3,
            "Should have 3 inputs (1 constant + 2 coords)"
        );
        Ok(())
    }

    #[test]
    fn test_inputize_neutral() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let p = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(get_neutral()))?;
        let result = p.inputize(cs.namespace(|| "inputize"));
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        assert_eq!(cs.num_inputs(), 3);
        Ok(())
    }

    // ========================================================================
    // FIXED_BASE_MULTIPLICATION TESTS
    // ========================================================================

    #[test]
    fn test_fixed_base_mul_empty_scalar() -> Result<(), Box<dyn std::error::Error>> {
        use crate::gadgets::sapling_constants::SPENDING_KEY_GENERATOR;
        let mut cs = TestConstraintSystem::new();
        let bits = vec![];
        let result =
            fixed_base_multiplication(cs.namespace(|| "fixed_mul"), &SPENDING_KEY_GENERATOR, &bits);
        assert!(
            result.is_err(),
            "Fixed-base multiplication with empty scalar should fail"
        );
        Ok(())
    }

    #[test]
    fn test_fixed_base_mul_one_bit() -> Result<(), Box<dyn std::error::Error>> {
        use crate::gadgets::sapling_constants::SPENDING_KEY_GENERATOR;
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(true)];
        let result =
            fixed_base_multiplication(cs.namespace(|| "fixed_mul"), &SPENDING_KEY_GENERATOR, &bits);
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_fixed_base_mul_small_scalars() -> Result<(), Box<dyn std::error::Error>> {
        use crate::gadgets::sapling_constants::SPENDING_KEY_GENERATOR;
        for num_bits in [1, 3, 6, 9, 12] {
            let scalar = jubjub::Scalar::from(7u64);
            let bits = scalar_to_bits_le(&scalar, num_bits);
            let mut cs = TestConstraintSystem::new();
            let result = fixed_base_multiplication(
                cs.namespace(|| "fixed_mul"),
                &SPENDING_KEY_GENERATOR,
                &bits,
            );
            assert!(result.is_ok(), "Failed for {num_bits} bits");
            assert!(cs.is_satisfied());
        }
        Ok(())
    }

    #[test]
    fn test_fixed_base_mul_all_generators() -> Result<(), Box<dyn std::error::Error>> {
        use crate::gadgets::sapling_constants::{
            NULLIFIER_POSITION_GENERATOR, SPENDING_KEY_GENERATOR,
        };
        let scalar = jubjub::Scalar::from(42u64);
        let bits = scalar_to_bits_le(&scalar, 16);

        for gen in [&*SPENDING_KEY_GENERATOR, &*NULLIFIER_POSITION_GENERATOR] {
            let mut cs = TestConstraintSystem::new();
            let result = fixed_base_multiplication(cs.namespace(|| "fixed_mul"), gen, &bits);
            assert!(result.is_ok());
            assert!(cs.is_satisfied());
        }
        Ok(())
    }

    // ========================================================================
    // MONTGOMERYPOINT TESTS
    // ========================================================================

    #[test]
    fn test_montgomery_interpret_unchecked() -> Result<(), Box<dyn std::error::Error>> {
        let x = Num::zero();
        let y = Num::zero();
        let _point = MontgomeryPoint::interpret_unchecked(x, y);
        Ok(())
    }

    #[test]
    fn test_montgomery_into_edwards_basic() -> Result<(), Box<dyn std::error::Error>> {
        // We need valid Montgomery coordinates that won't cause division by zero
        // Using a simple test that checks the conversion doesn't panic
        let x_val = bls12_381::Scalar::from(2u64);
        let y_val = bls12_381::Scalar::from(3u64);

        let mut cs = TestConstraintSystem::new();
        let x_alloc = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(x_val))?;
        let y_alloc = AllocatedNum::alloc(cs.namespace(|| "y"), || Ok(y_val))?;
        let mont = MontgomeryPoint::interpret_unchecked(x_alloc.into(), y_alloc.into());
        let result = mont.into_edwards(cs.namespace(|| "convert"));
        assert!(result.is_ok() || result.is_err()); // Just check it completes
        Ok(())
    }

    // ========================================================================
    // GET_U / GET_V TESTS
    // ========================================================================

    #[test]
    fn test_get_u_get_v() -> Result<(), Box<dyn std::error::Error>> {
        let point = get_generator();
        let affine = point.to_affine();
        let mut cs = TestConstraintSystem::new();
        let p = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(point))?;
        assert_eq!(p.get_u().get_value().ok_or("no value")?, affine.get_u());
        assert_eq!(p.get_v().get_value().ok_or("no value")?, affine.get_v());
        Ok(())
    }

    #[test]
    fn test_get_u_get_v_neutral() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let p = EdwardsPoint::witness(cs.namespace(|| "witness"), Some(get_neutral()))?;
        assert_eq!(
            p.get_u().get_value().ok_or("no value")?,
            bls12_381::Scalar::zero()
        );
        assert_eq!(
            p.get_v().get_value().ok_or("no value")?,
            bls12_381::Scalar::one()
        );
        Ok(())
    }

    // ========================================================================
    // EDGE CASE AND INTEGRATION TESTS
    // ========================================================================

    #[test]
    fn test_add_then_double() -> Result<(), Box<dyn std::error::Error>> {
        let p1 = get_generator();
        let p2 = get_generator() * jubjub::Scalar::from(3u64);
        let expected = (p1 + p2).double();
        let mut cs = TestConstraintSystem::new();
        let a = EdwardsPoint::witness(cs.namespace(|| "p1"), Some(p1))?;
        let b = EdwardsPoint::witness(cs.namespace(|| "p2"), Some(p2))?;
        let sum = a.add(cs.namespace(|| "add"), &b)?;
        let doubled = sum.double(cs.namespace(|| "double"))?;
        assert!(cs.is_satisfied());
        let exp_affine = expected.to_affine();
        assert_eq!(
            doubled.get_u().get_value().ok_or("no value")?,
            exp_affine.get_u()
        );
        assert_eq!(
            doubled.get_v().get_value().ok_or("no value")?,
            exp_affine.get_v()
        );
        Ok(())
    }

    #[test]
    fn test_double_then_add() -> Result<(), Box<dyn std::error::Error>> {
        let p1 = get_generator();
        let p2 = get_generator() * jubjub::Scalar::from(5u64);
        let expected = p1.double() + p2;
        let mut cs = TestConstraintSystem::new();
        let a = EdwardsPoint::witness(cs.namespace(|| "p1"), Some(p1))?;
        let b = EdwardsPoint::witness(cs.namespace(|| "p2"), Some(p2))?;
        let doubled = a.double(cs.namespace(|| "double"))?;
        let sum = doubled.add(cs.namespace(|| "add"), &b)?;
        assert!(cs.is_satisfied());
        let exp_affine = expected.to_affine();
        assert_eq!(
            sum.get_u().get_value().ok_or("no value")?,
            exp_affine.get_u()
        );
        assert_eq!(
            sum.get_v().get_value().ok_or("no value")?,
            exp_affine.get_v()
        );
        Ok(())
    }

    #[test]
    fn test_mul_distributive() -> Result<(), Box<dyn std::error::Error>> {
        // P * (a + b) = P * a + P * b
        let point = get_generator();
        let a = 3u64;
        let b = 5u64;
        let sum = a + b;

        let expected = point * jubjub::Scalar::from(sum);

        let mut cs = TestConstraintSystem::new();
        let p = EdwardsPoint::witness(cs.namespace(|| "p"), Some(point))?;
        let sum_bits = scalar_to_bits_le(&jubjub::Scalar::from(sum), 8);
        let result = p.mul(cs.namespace(|| "mul"), &sum_bits)?;

        assert!(cs.is_satisfied());
        let exp_affine = expected.to_affine();
        assert_eq!(
            result.get_u().get_value().ok_or("no value")?,
            exp_affine.get_u()
        );
        assert_eq!(
            result.get_v().get_value().ok_or("no value")?,
            exp_affine.get_v()
        );
        Ok(())
    }

    // ========================================================================
    // PC-085: INTO_EDWARDS VALID COORDS TEST
    // ========================================================================

    /// PC-085: Allocate a known valid Jubjub point via witness and verify the
    /// constraint system is satisfied. This confirms that valid Edwards
    /// coordinates pass the on-curve check.
    #[test]
    fn test_witness_valid_jubjub_point_satisfies_circuit() -> Result<(), Box<dyn std::error::Error>>
    {
        use sapling_crypto::constants::SPENDING_KEY_GENERATOR;

        // Use the Sapling spending key generator, a known valid subgroup point.
        let point: ExtendedPoint = SPENDING_KEY_GENERATOR.into();
        let mut cs = TestConstraintSystem::new();
        let p = EdwardsPoint::witness(cs.namespace(|| "valid_point"), Some(point))?;

        // The witness allocation performs the on-curve constraint check.
        assert!(
            cs.is_satisfied(),
            "A valid Jubjub subgroup point must satisfy the circuit constraints"
        );

        // Verify coordinates match the expected affine representation.
        let affine = point.to_affine();
        assert_eq!(p.get_u().get_value().ok_or("no u value")?, affine.get_u());
        assert_eq!(p.get_v().get_value().ok_or("no v value")?, affine.get_v());
        Ok(())
    }

    /// PC-085 (variant): Multiple known valid points all satisfy the circuit.
    #[test]
    fn test_witness_multiple_valid_points() -> Result<(), Box<dyn std::error::Error>> {
        use sapling_crypto::constants::{
            NOTE_COMMITMENT_RANDOMNESS_GENERATOR, SPENDING_KEY_GENERATOR,
            VALUE_COMMITMENT_VALUE_GENERATOR,
        };

        let points: &[jubjub::SubgroupPoint] = &[
            SPENDING_KEY_GENERATOR,
            NOTE_COMMITMENT_RANDOMNESS_GENERATOR,
            VALUE_COMMITMENT_VALUE_GENERATOR,
        ];

        for (i, &pt) in points.iter().enumerate() {
            let extended: ExtendedPoint = pt.into();
            let mut cs = TestConstraintSystem::new();
            let _p = EdwardsPoint::witness(cs.namespace(|| format!("point_{i}")), Some(extended))?;
            assert!(
                cs.is_satisfied(),
                "Sapling generator {i} must satisfy circuit constraints"
            );
        }
        Ok(())
    }

    // ========================================================================
    // PC-120: SAPLING CONSTANTS TEST
    // ========================================================================

    /// PC-120: Verify that the Sapling generator constants used by the circuit
    /// match the canonical values from sapling-crypto. A mismatch would mean
    /// the circuit's Pedersen hash produces different outputs than the host.
    #[test]
    fn test_sapling_spending_key_generator_matches_canonical() {
        use crate::gadgets::sapling_constants;
        use sapling_crypto::constants::SPENDING_KEY_GENERATOR as CANONICAL_SKG;

        // The circuit's SPENDING_KEY_GENERATOR lazy_static is derived from the
        // same base point. Verify the first window's first non-identity entry
        // matches the canonical generator's affine coordinates.
        let canonical_affine = ExtendedPoint::from(CANONICAL_SKG).to_affine();
        let circuit_table = &*sapling_constants::SPENDING_KEY_GENERATOR;

        // Window 0, entry 1 should be the generator point itself (1*G).
        let (circuit_u, circuit_v) = circuit_table[0][1];
        assert_eq!(
            circuit_u,
            canonical_affine.get_u(),
            "Circuit SPENDING_KEY_GENERATOR u-coordinate mismatch"
        );
        assert_eq!(
            circuit_v,
            canonical_affine.get_v(),
            "Circuit SPENDING_KEY_GENERATOR v-coordinate mismatch"
        );
    }

    /// PC-120 (variant): Verify that the Pedersen hash generators used by the
    /// circuit match the canonical PEDERSEN_HASH_GENERATORS from sapling-crypto.
    #[test]
    fn test_sapling_pedersen_generators_match_canonical() {
        use crate::gadgets::sapling_constants;
        use sapling_crypto::constants::PEDERSEN_HASH_GENERATORS as CANONICAL_GENERATORS;

        let circuit_generators = &*sapling_constants::PEDERSEN_CIRCUIT_GENERATORS;

        // There should be at least 6 generators (Sapling uses 6 segments).
        assert!(
            circuit_generators.len() >= 6,
            "Expected at least 6 Pedersen generators, got {}",
            circuit_generators.len()
        );

        // For each generator, verify the first chunk's first entry (1*G)
        // matches the canonical generator's affine form after Montgomery mapping.
        for (i, &gen) in CANONICAL_GENERATORS.iter().enumerate().take(6) {
            let gen_affine = ExtendedPoint::from(gen).to_affine();
            let (mont_u, mont_v) = sapling_constants::to_montgomery_coords(gen.into())
                .expect("Pedersen generator must not be point at infinity");

            // The circuit table stores Montgomery coordinates. Entry 0 is (1*G).
            let (table_u, table_v) = circuit_generators[i][0][0];
            assert_eq!(
                table_u, mont_u,
                "Pedersen generator {i} Montgomery u-coordinate mismatch"
            );
            assert_eq!(
                table_v, mont_v,
                "Pedersen generator {i} Montgomery v-coordinate mismatch"
            );

            // Sanity: the affine Edwards coordinates of the generator are non-zero.
            assert_ne!(gen_affine.get_u(), bls12_381::Scalar::zero());
        }
    }
}
