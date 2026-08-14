Herringfish Cryptanalysis & Statistical Methodology v0.1

Document status: Research methodology
Version: 0.1
Project: Herringfish
Scope: Differential cryptanalysis, linear cryptanalysis, statistical sampling, experimental interpretation
Applies to: Herringfish Feistel ARX and future Herringfish cipher prototypes

1. Purpose

This document defines the mathematical and statistical methodology used to evaluate Herringfish cryptographic constructions.

Its primary purpose is to establish a rigorous distinction between:

Mathematical properties.
Experimental observations.
Statistical estimates.
Cryptanalytic evidence.
Security bounds.
Security claims.

The methodology is intended to make Herringfish experiments reproducible and prevent incorrect interpretation of finite-sample results.

The guiding principle is:

Measure what the experiment actually measures, and do not claim more than the evidence supports.

2. Cryptographic Notation

Throughout this document:

Symbol	Meaning
E
K
	​

	Encryption function under key K
D
K
	​

	Decryption function under key K
P	Plaintext
C	Ciphertext
K	Cryptographic key
Δ
in
	​

	Input difference
Δ
out
	​

	Output difference
α	Linear input mask
β	Linear output mask
N	Number of statistical samples

p
^
	​

	Empirical probability estimate
p	Underlying probability
bias	Linear approximation bias
HW(x)	Hamming weight of x

For Herringfish Feistel ARX v0.2:

∣P∣=∣C∣=128

and therefore:

P,C∈{0,1}
128
.
3. Experimental Philosophy

Cryptanalysis experiments should be treated as hypothesis tests.

The process is:

Hypothesis
    ↓
Mathematical model
    ↓
Experiment
    ↓
Observation
    ↓
Statistical analysis
    ↓
Attempted falsification
    ↓
Conclusion

A successful experiment does not automatically establish security.

For example:

"No high-probability differential was detected."

is valid.

Whereas:

"The cipher has no high-probability differentials."

requires substantially stronger evidence.

4. Differential Cryptanalysis
4.1 Input Difference

Let:

E
K
	​

:{0,1}
128
→{0,1}
128

be a reduced-round Herringfish encryption function.

Fix a nonzero input difference:

Δ
in
	​

∈{0,1}
128
.

For a uniformly random plaintext:

P←{0,1}
128
,

construct:

P
2
	​

=P⊕Δ
in
	​

.

The corresponding ciphertexts are:

C=E
K
	​

(P)

and:

C
2
	​

=E
K
	​

(P
2
	​

).

The resulting output difference is:

Δ
out
	​

=C⊕C
2
	​

.

Therefore:

Δ
out
	​

=E
K
	​

(P)⊕E
K
	​

(P⊕Δ
in
	​

)
	​

5. Differential Probability

For a fixed key K, input difference Δ
in
	​

, and output difference Δ
out
	​

, define:

p
K
	​

(Δ
in
	​

→Δ
out
	​

)=
P
Pr
	​

[E
K
	​

(P)⊕E
K
	​

(P⊕Δ
in
	​

)=Δ
out
	​

]
	​


where P is uniformly distributed over:

{0,1}
128
.

This is the differential probability being estimated by the Herringfish differential sampler.

6. Empirical Differential Estimator

The sampler draws:

N

independent plaintext values:

P
1
	​

,P
2
	​

,…,P
N
	​

.

For each sample:

P
i
′
	​

=P
i
	​

⊕Δ
in
	​

.

The corresponding output difference is:

Δ
out,i
	​

=E
K
	​

(P
i
	​

)⊕E
K
	​

(P
i
′
	​

).

For a fixed output difference Δ
out
	​

, define:

I
i
	​

(Δ
out
	​

)={
1,
0,
	​

Δ
out,i
	​

=Δ
out
	​

otherwise
	​


The empirical differential probability is:

p
^
	​

K
	​

(Δ
in
	​

→Δ
out
	​

)=
N
1
	​

i=1
∑
N
	​

I
i
	​

(Δ
out
	​

)
	​


or equivalently:

p
^
	​

K
	​

(Δ
in
	​

→Δ
out
	​

)=
N
#{i:Δ
out,i
	​

=Δ
out
	​

}
	​

	​


This is the estimator implemented by the differential sampler.

7. Maximum Observed Differential Probability

For a fixed input difference, the sampler determines the most frequently observed output difference:

p
^
	​

max
	​

(Δ
in
	​

)=
Δ
out
	​

max
	​

p
^
	​

K
	​

(Δ
in
	​

→Δ
out
	​

)
	​


If multiple input differences are tested, the experiment may report:

p
^
	​

max
	​

=
Δ
in
	​

∈D
max
	​

p
^
	​

max
	​

(Δ
in
	​

)
	​


where D is the set of tested input differences.

For Herringfish experiments, D may include input differences with:

HW(Δ
in
	​

)=1
HW(Δ
in
	​

)=2

and:

HW(Δ
in
	​

)=4.
8. Differential Sampling in Herringfish

The current experimental configuration uses:

N=100,000

plaintext pairs per tested input difference.

The experiment therefore estimates the empirical distribution:

Δ
out
	​

=E
K
	​

(P)⊕E
K
	​

(P⊕Δ
in
	​

)

for the chosen Δ
in
	​

.

The sampler is particularly useful for detecting unexpected concentrations of output differences.

It is not, by itself, a practical method for precisely estimating extremely small differential probabilities in a 128-bit cipher.

9. Random-Permutation Null Model

For an ideal random permutation over 128-bit blocks, a fixed nonzero input difference produces an output-difference distribution that is approximately uniform over the 128-bit difference space, subject to the structural constraints of a permutation.

The output-difference domain contains:

2
128

possible values.

For a particular fixed output difference, the approximate null probability is:

p
0
	​

≈2
−128
	​


which is approximately:

5.42×10
−39
.

Important: 2
−128
 is approximately 5.42×10
−39
, not 5.42×10
−20
.

10. Sparse Sampling Regime

The Herringfish sampler uses:

N=100,000

samples, while the output-difference domain contains:

2
128

possible values.

Therefore:

N≪2
128
.

This places the experiment in an extremely sparse occupancy regime.

Under the idealized uniform model, the expected number of occurrences of any particular output difference is:

λ=Np
0
	​

=
2
128
N
	​

.

For N=100,000:

λ≈2.94×10
−34
.

Thus, an individual output difference is extraordinarily unlikely to occur twice—or even once—under the idealized random model.

11. Interpretation of the Observed 10
−5
 Maximum

Suppose the sampler observes:

100,000 samples
1 occurrence of the most common output difference

Then:

p
^
	​

max
	​

=
100,000
1
	​

=10
−5
.

This does not mean that the cipher has a differential probability of 10
−5
.

Instead, 10
−5
 is the smallest nonzero empirical frequency that can be observed from a single occurrence in a sample of 100,000.

In a sparse 128-bit output space, this is an occupancy/sampling artifact.

If every observed output difference occurs exactly once:

p
^
	​

max
	​

=10
−5
.

Therefore:

An observed maximum of approximately 10
−5
 is consistent with a collision-free sample and should not be interpreted as a measured upper bound on the true differential probability.

12. What the Differential Sampler Can Detect

The sampler is effective at detecting differential probabilities sufficiently large to generate repeated observations.

For example, suppose:

p=10
−2
.

With:

N=100,000,

the expected number of observations is:

Np=1,000.

Such a differential would be immediately visible.

Similarly:

p=10
−3

would produce approximately:

100

observations.

However:

p=10
−5

produces only:

1

expected observation.

Therefore the experiment's detection capability decreases rapidly for rare events.

13. Binomial Model

For a fixed:

Δ
in
	​

,Δ
out
	​

,

the number of observations:

X=#{i:Δ
out,i
	​

=Δ
out
	​

}

can be modeled approximately as:

X∼Binomial(N,p)
	​


where:

p=p
K
	​

(Δ
in
	​

→Δ
out
	​

).

The estimator is:

p
^
	​

=
N
X
	​

.

Its expectation is:

E[
p
^
	​

]=p

and variance is:

Var(
p
^
	​

)=
N
p(1−p)
	​

.

Therefore:

SE(
p
^
	​

)=
N
p(1−p)
	​

	​

	​

14. Confidence Intervals for Differential Probabilities

For sufficiently large expected counts, a normal approximation may be used:

p
^
	​

±1.96
N
p
^
	​

(1−
p
^
	​

)
	​

	​

.

However, for extremely small counts, including:

X=0

or:

X=1,

the normal approximation is inappropriate.

Herringfish statistical tooling should therefore prefer exact or small-count methods such as:

Clopper–Pearson intervals.
Wilson intervals.
Poisson approximations where appropriate.

The method used should be explicitly recorded in experimental output.

15. Multiple Output Differences

The reported:

p
^
	​

max
	​


is a maximum over many possible output differences.

Therefore, its statistical behavior is not equivalent to the confidence interval of a single fixed output difference.

This distinction is important.

The experiment performs a search over the observed output-difference distribution.

Consequently:

A confidence interval computed for one fixed Δ
out
	​

 cannot automatically be applied to the maximum over all Δ
out
	​

.

16. Differential Trail Probability

The sampler described above estimates a differential probability for the complete reduced-round cipher.

This is different from the probability of an individual differential trail.

For a sequence of intermediate differences:

Δ
0
	​

,Δ
1
	​

,…,Δ
r
	​

,

a differential characteristic may have an approximate probability:

p
trail
	​

=
i=1
∏
r
	​

p
i
	​

	​


under the usual independence-style approximation used in differential trail analysis.

This approximation must be treated carefully because differential trails can form hulls containing multiple characteristics.

Therefore:

trail probability

=necessarily complete differential probability.
17. Differential Hulls

A differential:

Δ
in
	​

→Δ
out
	​


may be realized by many internal differential characteristics.

The complete differential probability is therefore conceptually:

p(Δ
in
	​

→Δ
out
	​

)=
T∈T
∑
	​

p(T)
	​


where T represents the relevant compatible differential trails.

This is why full differential analysis should eventually include automated trail and hull analysis rather than relying exclusively on random sampling.

18. Linear Cryptanalysis

Linear cryptanalysis examines correlations between selected input and output bit masks.

Let:

α,β∈{0,1}
128
.

The input mask is:

α

and the output mask is:

β.

Define the parity function:

parity(x)=
j=0
⨁
127
	​

x
j
	​

.

The masked input bit is:

α⋅P=parity(α∧P).

Similarly:

β⋅C=parity(β∧C).
19. Linear Approximation Event

The linear approximation is considered successful when:

α⋅P⊕β⋅C=0
	​


The corresponding event is:

E(α,β)={P:α⋅P⊕β⋅E
K
	​

(P)=0}.

Its probability is:

p
K
	​

(α,β)=
P
Pr
	​

[α⋅P⊕β⋅E
K
	​

(P)=0]
	​

20. Empirical Linear Estimator

The sampler draws:

N

random plaintexts:

P
1
	​

,…,P
N
	​

.

For each:

C
i
	​

=E
K
	​

(P
i
	​

).

Define:

I
i
	​

(α,β)={
1,
0,
	​

α⋅P
i
	​

⊕β⋅C
i
	​

=0
otherwise.
	​


Then:

p
^
	​

(α,β)=
N
1
	​

i=1
∑
N
	​

I
i
	​

(α,β)
	​


or:

p
^
	​

(α,β)=
N
#{i:α⋅P
i
	​

⊕β⋅C
i
	​

=0}
	​

	​

21. Linear Bias

For a perfectly random relationship:

p=
2
1
	​

.

The empirical linear bias is:

bias
(α,β)=
	​

p
^
	​

(α,β)−
2
1
	​

	​

	​


The corresponding signed correlation can be expressed as:

ρ
^
	​

(α,β)=2
p
^
	​

(α,β)−1
	​


and therefore:

∣
ρ
^
	​

∣=2
bias
	​

22. Statistical Noise of Linear Sampling

Under the random-function null:

p=
2
1
	​

.

Therefore:

SE=
N
(1/2)(1/2)
	​

	​


which simplifies to:

SE=
2
N
	​

1
	​

	​


For:

N=100,000,

this gives approximately:

SE≈0.001581.

A simple approximate 95% interval is:

2
1
	​

±1.96(0.001581)

or approximately:

0.5±0.00310
	​


Therefore, random sampling alone can naturally produce biases on the order of several 10
−3
.

23. Linear Sampling Methodology

The current Herringfish linear sampler evaluates a collection of randomly selected mask pairs:

(α,β).

For each pair, it estimates:

p
^
	​

(α,β)

and:

bias
(α,β).

The reported maximum is:

bias
max
	​

=
(α,β)∈M
max
	​

bias
(α,β)
	​


where M is the set of sampled mask pairs.

Current experiments may use:

∣M∣=10

random mask pairs per tested round count.

24. Multiple-Testing Consideration

The maximum observed bias over multiple random masks is expected to be larger than the bias of a single randomly selected mask.

Therefore:

bias
max
	​


must be interpreted in the context of:

Number of masks tested.
Number of plaintext samples per mask.
Mask-selection methodology.
Multiple-comparison effects.

Increasing the number of tested masks increases the probability of observing an apparently large statistical deviation by chance.

For serious linear cryptanalysis, random mask sampling should eventually be replaced or supplemented by systematic mask search.

25. S-box Differential Analysis

For an 8-bit S-box:

S:{0,1}
8
→{0,1}
8
,

the differential distribution table is defined as:

DDT[Δx][Δy]=#{x:S(x)⊕S(x⊕Δx)=Δy}
	​


for:

Δx,Δy∈{0,1}
8
.

The maximum differential probability is:

DP
max
	​

=
256
max
Δx

=0,Δy
	​

DDT[Δx][Δy]
	​

	​


For the Herringfish v0.2 acceptance criterion:

DDT
max
	​

≤4

and therefore:

DP
max
	​

≤
256
4
	​

=0.015625.
26. S-box Linear Approximation Table

For an 8-bit S-box, define:

LAT[α][β]=#{x:α⋅x=β⋅S(x)}.

The deviation from the ideal count of 128 is:

bias
count
	​

=∣LAT[α][β]−128∣.

The corresponding probability bias is:

bias
prob
	​

=
256
∣LAT[α][β]−128∣
	​

	​


The precise terminology used in implementation reports must distinguish LAT count bias from probability bias.

27. Diffusion Analysis

The Herringfish v0.2 intra-round diffusion layer is:

out
i
	​

=in
i
	​

⊕in
(i+1)mod8
	​

⊕in
(i+3)mod8
	​

	​


for:

i∈{0,…,7}.

This transformation is linear over:

GF(2).

Therefore it can be represented as an 8×8 binary matrix:

D.

The matrix should be analyzed for:

Rank.
Kernel.
Invertibility.
Branch number.
Active-byte propagation.
Iterated diffusion.
28. Branch Number

For a linear transformation D, the branch number can be defined as:

B(D)=
x

=0
min
	​

(HW(x)+HW(D(x)))
	​


when measuring byte activity using the appropriate byte-level Hamming weight.

The branch number provides information about how many active components are forced through a linear layer.

For Herringfish, this should eventually be evaluated exactly rather than estimated by random sampling.

29. Active S-box Analysis

Differential and linear security can be related to the number of active S-boxes.

If the S-box has maximum differential probability:

DP
max
	​

,

and a trail contains a active S-boxes, a basic upper-bound heuristic is:

P
trail
	​

≤(DP
max
	​

)
a
	​


assuming the trail's individual S-box transitions are bounded by the S-box maximum.

Similarly, if:

LP
max
	​


is the maximum absolute linear correlation of the S-box, then a basic trail estimate is:

∣C
trail
	​

∣≤(LP
max
	​

)
a
	​


under the standard trail-composition model.

These are useful analytical tools but do not automatically establish full-cipher security because of differential and linear hull effects.

30. Reduced-Round Analysis

Herringfish should be analyzed progressively:

1 round
 ↓
2 rounds
 ↓
3 rounds
 ↓
...
 ↓
16 rounds

The purpose is to determine the strongest known attack as a function of the number of rounds.

For every attack, record:

Property	Required
Rounds attacked	Yes
Attack type	Yes
Data complexity	Yes
Time complexity	Yes
Memory complexity	Yes
Success probability	Yes
Key assumptions	Yes
Structural assumptions	Yes
Practicality	Yes
31. Security Margin

Let:

R
full
	​


be the number of rounds in the complete construction.

Let:

R
attack
	​


be the number of rounds reached by the strongest known attack.

A simple round-count gap is:

M=R
full
	​

−R
attack
	​

	​


For Herringfish v0.2:

R
full
	​

=16.

If the strongest demonstrated attack reaches 8 rounds:

M=16−8=8.

This is a round-count gap, not automatically a formal security margin.

The quality of the margin depends on the attack's complexity and how realistically it extends to additional rounds.

32. Statistical Terminology

Herringfish documentation should use the following terminology carefully.

Observation

A result directly measured by an experiment.

Example:

"The most frequent observed output difference occurred once in 100,000 samples."

Estimate

A statistical approximation to an unknown quantity.

Example:

p
^
	​

=
N
X
	​

.
Bound

A mathematically justified upper or lower limit.

Example:

p≤B.
Hypothesis

A proposition being tested.

Example:

"The reduced-round construction exhibits no differential concentration above a specified threshold."

Security Claim

A statement about resistance to an attack model.

Security claims require substantially stronger evidence than statistical observations.

33. Reproducibility Requirements

Every cryptanalytic experiment should record:

Cipher version.
Source revision/commit.
Key.
Round count.
Input difference(s).
Input Hamming weight.
Number of samples.
Random-number generator.
RNG seed where applicable.
Output-difference counting method.
Mask-selection method.
Statistical estimator.
Confidence-interval method.
Hardware.
Software version.
Compiler version where relevant.

This allows experiments to be reproduced independently.

34. Recommended Differential Experiment Output

A future Herringfish differential experiment should produce output resembling:

Herringfish Differential Analysis
==================================


Cipher: Herringfish Feistel ARX
Version: 0.2
Rounds: 8
Block size: 128 bits


Input difference:
  Hamming weight: 1
  Delta_in: <hex>


Samples:
  100000


Unique output differences:
  <count>


Maximum observed frequency:
  <count>


Maximum empirical probability:
  <value>


Collision count:
  <count>


Statistical interpretation:
  <description>


Conclusion:
  <description>

This is preferable to reporting only:

max prob = 0.000010

because the latter can easily be misinterpreted.

35. Recommended Linear Experiment Output

A future linear experiment should report:

Herringfish Linear Analysis
===========================


Cipher: Herringfish Feistel ARX
Version: 0.2
Rounds: 8


Masks tested:
  10


Samples per mask:
  100000


Maximum observed bias:
  <value>


Mask pair:
  Alpha: <hex>
  Beta:  <hex>


Observed probability:
  <value>


Expected random bias:
  <value>


Statistical significance:
  <value>


Conclusion:
  <description>
36. Current Herringfish Experimental Configuration

The current research configuration includes:

Differential
Samples per input difference: 100,000
Input Hamming weights:        1, 2, 4
Reduced rounds:               4, 6, 8
Linear
Masks per round count:        10
Samples per mask:             100,000
Reduced rounds:               4, 6, 8

These experiments are considered screening experiments.

They are not substitutes for full differential or linear cryptanalysis.

37. Current Interpretation of Results

Current Herringfish Feistel ARX experiments have observed approximately:

p
^
	​

max
	​

≈10
−5

in the 100,000-sample differential experiments.

Given the 128-bit output-difference domain, this is consistent with the sampling floor produced by a single observed occurrence:

100000
1
	​

=10
−5
.

The appropriate interpretation is:

No high-probability differential concentration was detected in the tested reduced-round experiments.

It is not:

The maximum differential probability is 10
−5
.

Similarly, observed linear biases should be compared against the expected sampling variation:

SE=
2
N
	​

1
	​

.

For N=100,000:

SE≈0.001581.

Therefore, biases of only a few 10
−3
 can arise naturally from finite sampling.

38. What Sampling Cannot Establish

Finite random sampling cannot establish:

Absence of all differential characteristics.
Absence of all linear approximations.
Maximum differential probability.
Maximum linear correlation.
Security against adaptive attacks.
Security against related-key attacks.
Security against chosen-ciphertext attacks.
Security against side-channel attacks.
Production security.

Sampling is an experimental instrument, not a proof system.

39. Required Next-Level Cryptanalysis

The statistical samplers should eventually be complemented by:

Differential
Exact S-box DDT.
Differential trail search.
Differential characteristic enumeration.
Active S-box analysis.
Differential hull analysis.
Automated reduced-round attacks.
Structured input-difference search.
Linear
Exact S-box LAT.
Linear trail search.
Linear hull analysis.
Automated mask search.
Correlation analysis.
Reduced-round attacks.
Structural
Slide attacks.
Integral attacks.
Impossible differentials.
Zero-correlation attacks.
Rotational analysis where applicable.
Symmetry analysis.
Fixed-point analysis.
Key Schedule
Related-key attacks.
Weak-key search.
Key-schedule correlation analysis.
Cross-round dependency analysis.
40. Security Reporting Standard

Herringfish research reports should classify conclusions using four levels.

Level 1 — Observation

Example:

"No repeated output difference occurred in 100,000 samples."

Level 2 — Statistical Evidence

Example:

"The observed distribution is consistent with the tested random-permutation model under the stated sampling methodology."

Level 3 — Cryptanalytic Result

Example:

"A differential characteristic covering 10 rounds with estimated probability 2
−48
 was identified."

Level 4 — Security Result

Example:

"A practical attack breaks the 12-round construction with 2
40
 chosen plaintexts."

Only Level 3 and Level 4 results should normally be described as cryptanalytic security results.

41. Core Statistical Principle

The central principle of Herringfish statistical analysis is:

Finite samples provide evidence, not certainty.
	​


Every result must therefore be interpreted relative to:

Sample size.
Search space.
Null model.
Number of tests.
Statistical estimator.
Attack model.
Experimental assumptions.
42. Core Cryptanalytic Principle

The central cryptanalytic principle is:

Attack the construction, not the hypothesis.
	​


If the experiment confirms the expected behavior, continue looking for stronger attacks.

If the experiment contradicts the expected behavior, investigate the contradiction.

If an attack succeeds, document it.

A successful attack is a valuable result because it provides information for the next Herringfish design iteration.

43. Research Loop

The complete methodology is:

                 ┌───────────────┐
                 │    Design     │
                 └───────┬───────┘
                         │
                         ▼
                 ┌───────────────┐
                 │  Formalize    │
                 └───────┬───────┘
                         │
                         ▼
                 ┌───────────────┐
                 │  Implement    │
                 └───────┬───────┘
                         │
                         ▼
                 ┌───────────────┐
                 │   Validate    │
                 └───────┬───────┘
                         │
                         ▼
                 ┌───────────────┐
                 │    Measure    │
                 └───────┬───────┘
                         │
                         ▼
                 ┌───────────────┐
                 │    Attack     │
                 └───────┬───────┘
                         │
              ┌──────────┴──────────┐
              │                     │
              ▼                     ▼
       Weakness found          No weakness
              │                     │
              ▼                     ▼
          Analyze              Increase
          weakness             analysis
              │                     │
              └──────────┬──────────┘
                         ▼
                    Revise design
                         │
                         ▼
                      Repeat
44. Final Statement

Herringfish is an experimental cryptographic research project.

Its security must emerge from:

Mathematical analysis.
Cryptanalytic attacks.
Statistical evidence.
Independent reproduction.
Implementation review.
Continued attempts at falsification.

The project should never equate:

random-looking output

with:

cryptographic security.

Likewise:

no observed attack

does not imply:

no possible attack.

The goal is to progressively replace uncertainty with evidence.

Design it. Implement it. Measure it. Attack it. Improve it.

Suggested filename
docs/cryptanalysis/statistical_methodology_v0.1.md

I would keep this separate from the Feistel v0.2 specification. The cipher specification answers “What is Herringfish?”; this document answers “How do we mathematically test Herringfish, and how do we interpret the results?”.

That separation will become particularly valuable once Herringfish has multiple constructions (Feistel, SPN, etc.), because the same statistical/cryptanalytic methodology can then be applied to all of them.