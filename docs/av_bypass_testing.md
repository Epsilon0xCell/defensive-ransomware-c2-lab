# Fake AV bypass testing: what this is, and what it is not

This bench tests bypass techniques against THIS REPO'S fake AV
(lab/fake_av.py), a small model scanner with three tiers: naive
(extension and magic), standard (plus marker signature and entropy),
and behavioural (plus host telemetry).

It is not a bypass for any real antivirus or EDR product, it does
not test against one, and nothing in it is designed to evade one.
The case files are inert dummy artifacts from the lab sandbox, and
every transform applied to them (rename, extension change, text
encoding, split, partial encryption) is logged as telemetry, which
is exactly what the behavioural tier consumes.

Why build it this way: the portfolio lesson, and the real-world
lesson from the research report, is that content scanning alone
loses to trivial transforms, and behaviour is what catches them.
The scorecard makes that measurable: run python -m lab.run_lab and
read reports/, or call the bench directly. A miss at a tier is a
finding about the tier and a ticket to improve the detection, which
is the defensive work this repo exists to teach.

Adding a case: add the transform in lab/bypass_tests.py with its
telemetry event, its lesson text, and a test asserting which tiers
should catch or miss it, and why.
