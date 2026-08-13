# Test data

## `pcaps/`

One synthetic capture per attack Network Defender detects, plus `benign.pcap`.
Each is built to cross exactly one detector's threshold in
`config/detectors.json` and to stay clear of every other detector's, so the
end-to-end suite can assert on the full alert set rather than just on presence.

Regenerate them with:

```
uv run python scripts/generate_test_pcaps.py
```

The generator is seeded and uses a fixed base timestamp, so regenerating
without changing a scenario produces byte-identical files. They are committed
rather than built at test time so a change in Scapy's defaults shows up as a
diff to review, instead of as traffic that has quietly stopped resembling the
attack it is named after.

## `golden/`

Expected detector output for each capture above, used for regression
comparison. See `tests/e2e/` for how a mismatch is reported and how to
refresh a golden file deliberately.
