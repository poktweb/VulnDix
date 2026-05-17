from vulndix.payload_updater import merge_unique, parse_payload_lines


def test_parse_skips_comments():
    text = "# comment\n' OR 1=1\n\nDROP TABLE users"
    lines = parse_payload_lines(text)
    assert "' OR 1=1" in lines
    assert not any("DROP TABLE" in x for x in lines)


def test_merge_unique():
    assert merge_unique(["a", "b"], ["b", "c"]) == ["a", "b", "c"]
