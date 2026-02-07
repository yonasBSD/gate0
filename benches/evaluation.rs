//! Criterion benchmarks for Gate0 evaluation performance.
//!
//! Run with: cargo bench
//!
//! These benchmarks verify the sub-50µs evaluation claim for
//! typical policy configurations.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use gate0::{Condition, Effect, Matcher, Policy, ReasonCode, Request, Rule, Target, Value};

/// Build a minimal policy: single allow-all rule.
fn minimal_policy() -> Policy<'static> {
    Policy::builder()
        .rule(Rule::allow(Target::any(), ReasonCode(1)))
        .build()
        .unwrap()
}

/// Build a typical RBAC policy: 5 rules with conditions.
fn typical_rbac_policy() -> Policy<'static> {
    Policy::builder()
        .rule(Rule::new(
            Effect::Allow,
            Target::any(),
            Some(Condition::Equals {
                attr: "role",
                value: Value::String("superadmin"),
            }),
            ReasonCode(100),
        ))
        .rule(Rule::new(
            Effect::Allow,
            Target {
                principal: Matcher::Any,
                action: Matcher::OneOf(&["read", "list", "describe"]),
                resource: Matcher::Any,
            },
            Some(Condition::Equals {
                attr: "role",
                value: Value::String("viewer"),
            }),
            ReasonCode(101),
        ))
        .rule(Rule::new(
            Effect::Allow,
            Target {
                principal: Matcher::Any,
                action: Matcher::OneOf(&["read", "write", "update", "delete"]),
                resource: Matcher::Any,
            },
            Some(Condition::Equals {
                attr: "role",
                value: Value::String("editor"),
            }),
            ReasonCode(102),
        ))
        .rule(Rule::new(
            Effect::Deny,
            Target {
                principal: Matcher::Any,
                action: Matcher::Exact("delete"),
                resource: Matcher::Any,
            },
            Some(Condition::Equals {
                attr: "mfa_verified",
                value: Value::Bool(false),
            }),
            ReasonCode(403),
        ))
        .rule(Rule::new(
            Effect::Allow,
            Target {
                principal: Matcher::Any,
                action: Matcher::OneOf(&["read"]),
                resource: Matcher::Any,
            },
            None,
            ReasonCode(200),
        ))
        .build()
        .unwrap()
}

/// Build a worst-case policy: many rules, deep conditions.
fn heavy_policy() -> Policy<'static> {
    let mut builder = Policy::builder();
    
    // 50 rules with conditions
    for i in 0..50 {
        builder = builder.rule(Rule::new(
            if i % 5 == 0 { Effect::Deny } else { Effect::Allow },
            Target {
                principal: Matcher::Exact("user"),
                action: Matcher::Exact("action"),
                resource: Matcher::Exact("resource"),
            },
            Some(Condition::And(
                Box::new(Condition::Equals {
                    attr: "attr_a",
                    value: Value::Bool(true),
                }),
                Box::new(Condition::Equals {
                    attr: "attr_b",
                    value: Value::Int(i as i64),
                }),
            )),
            ReasonCode(i as u32),
        ));
    }
    
    // Fallback allow
    builder = builder.rule(Rule::allow(Target::any(), ReasonCode(999)));
    
    builder.build().unwrap()
}

fn bench_minimal_evaluation(c: &mut Criterion) {
    let policy = minimal_policy();
    let request = Request::new("alice", "read", "document");
    
    c.bench_function("minimal_policy_evaluate", |b| {
        b.iter(|| {
            black_box(policy.evaluate(black_box(&request)))
        })
    });
}

fn bench_typical_rbac_evaluation(c: &mut Criterion) {
    let policy = typical_rbac_policy();
    
    // Request that matches the viewer role (middle of policy)
    let ctx: &[(&str, Value)] = &[
        ("role", Value::String("viewer")),
        ("mfa_verified", Value::Bool(true)),
    ];
    let request = Request::with_context("bob", "read", "doc-123", ctx);
    
    c.bench_function("typical_rbac_evaluate", |b| {
        b.iter(|| {
            black_box(policy.evaluate(black_box(&request)))
        })
    });
}

fn bench_typical_rbac_worst_case(c: &mut Criterion) {
    let policy = typical_rbac_policy();
    
    // Request that matches NO rules until fallback (worst case traversal)
    let ctx: &[(&str, Value)] = &[
        ("role", Value::String("unknown")),
        ("mfa_verified", Value::Bool(true)),
    ];
    let request = Request::with_context("guest", "execute", "secret", ctx);
    
    c.bench_function("typical_rbac_no_match", |b| {
        b.iter(|| {
            black_box(policy.evaluate(black_box(&request)))
        })
    });
}

fn bench_heavy_policy_evaluation(c: &mut Criterion) {
    let policy = heavy_policy();
    
    // Request that falls through all 50 rules to hit the fallback
    let ctx: &[(&str, Value)] = &[
        ("attr_a", Value::Bool(false)),
        ("attr_b", Value::Int(9999)),
    ];
    let request = Request::with_context("user", "action", "resource", ctx);
    
    c.bench_function("heavy_policy_50_rules", |b| {
        b.iter(|| {
            black_box(policy.evaluate(black_box(&request)))
        })
    });
}

fn bench_context_lookup(c: &mut Criterion) {
    let policy = typical_rbac_policy();
    
    // Varying context sizes
    let mut group = c.benchmark_group("context_size");
    
    for size in [2, 8, 32, 64] {
        let ctx: Vec<(&str, Value)> = (0..size)
            .map(|i| {
                // Leak strings to get 'static lifetime for benchmark
                let key: &'static str = Box::leak(format!("attr_{}", i).into_boxed_str());
                (key, Value::Int(i as i64))
            })
            .collect();
        
        // Add the role attribute we actually match on
        let mut ctx = ctx;
        ctx.push(("role", Value::String("viewer")));
        
        let request = Request::with_context("user", "read", "doc", &ctx);
        
        group.bench_with_input(BenchmarkId::new("attrs", size), &request, |b, req| {
            b.iter(|| {
                black_box(policy.evaluate(black_box(req)))
            })
        });
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_minimal_evaluation,
    bench_typical_rbac_evaluation,
    bench_typical_rbac_worst_case,
    bench_heavy_policy_evaluation,
    bench_context_lookup,
);

criterion_main!(benches);
