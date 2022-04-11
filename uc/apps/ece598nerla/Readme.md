# ece598UC programming assignment

Implementation of MultiSession commit from Lindell

"Highly-Efficient Universally-Composable Commitments based on the DDH Assumption"

# Running Examples

`python env.py`

Includes:

* `env`: honest environment (for 2 sets of parties)
* `env_committer_crupt_bad_a`: corrupt committer that fails proof step a (for 2 sets of parties)
* `env_committer_crupt_bad_c`:
  * commit with 1 set of honest parties
  * corrupt committer that fails proof step c (for 2 sets of parties)
* `env_receiver_crupt`: corrupt receiver (for 2 sets of parties)

# Other

* distinguisher checks for equality of transcript (copied from examples)
* "a2z" and "p2z" are treated as the same in transcript
