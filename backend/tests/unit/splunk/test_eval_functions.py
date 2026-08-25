"""The ``eval`` function table and ``makeresults``, measured against Splunk 10.4.2.

Every expectation below was taken by running the expression on a real
instance and reading what came back — 233 of them, compared engine to engine.
Three behaviours are worth naming, because they are the ones a plausible
implementation gets wrong:

* **A typed null is not a missing field.** ``null()`` is a literal of type
  Invalid, and splunkd refuses it where a function wants a string or a
  number: ``upper(null())`` is an argument error. A field the row does not
  have is a *runtime* null, and makes the call null instead:
  ``upper(nosuchfield)`` leaves the field unassigned.
* **The types an expression can be seen to have are checked before it runs.**
  ``"1"+1`` never reaches a row — splunkd refuses two operands of different
  types — while ``field+1`` waits for the value and yields null if it is not
  a number.
* **``min`` and ``max`` order by where a value came from.** A quoted literal
  is text even when it reads as a number, so ``min("10", "9")`` is ``"10"``;
  a field holding ``10`` is the number, so ``max(field, 9)`` is ``10``.
"""
import pytest

from utils.splunk.spl_exec import execute_pipeline
from utils.splunk.spl_parser import parse_spl


def run(spl: str, rows: list[dict] | None = None) -> tuple[list[dict], list[dict]]:
    """Run a pipeline, returning its rows and messages."""
    return execute_pipeline(list(rows or []), parse_spl(spl))


def value(expression: str) -> object:
    """What ``eval v=<expression>`` assigns, or None if it assigns nothing."""
    rows, messages = run(f"| makeresults | eval v={expression} | table v")
    fatal = [m for m in messages if m["type"] == "FATAL"]
    if fatal:
        pytest.fail(f"unexpected failure: {fatal[0]['text']}")
    return rows[0].get("v") if rows else None


def failure(expression: str) -> str:
    """The FATAL text ``eval v=<expression>`` produces."""
    _rows, messages = run(f"| makeresults | eval v={expression}")
    fatal = [m for m in messages if m["type"] == "FATAL"]
    assert fatal, "expected the search to fail"
    return fatal[0]["text"]


class TestMultivalue:
    """``split`` and the family around it."""

    def test_split_returns_the_parts(self) -> None:
        assert value('split("a;b;c", ";")') == ["a", "b", "c"]

    def test_a_split_that_finds_no_separator_is_the_string(self) -> None:
        # Not a list of one: splunkd hands back the string itself.
        assert value('split("abc", ";")') == "abc"

    def test_mvindex_out_of_range_assigns_nothing(self) -> None:
        assert value('mvindex(split("a;b;c",";"), 9)') is None

    def test_mvindex_takes_a_range(self) -> None:
        assert value('mvindex(split("a;b;c",";"), 0, 1)') == ["a", "b"]

    def test_mvfilter_keeps_the_values_the_expression_holds_for(self) -> None:
        rows, _ = run(
            '| makeresults | eval m=split("a1;b;c2",";") '
            '| eval v=mvjoin(mvfilter(match(m,"\\d")),"-") | table v',
        )
        assert rows[0]["v"] == "a1-c2"

    def test_mvmap_replaces_each_value(self) -> None:
        rows, _ = run(
            '| makeresults | eval m=split("a;b",";") '
            '| eval v=mvjoin(mvmap(m,upper(m)),"-") | table v',
        )
        assert rows[0]["v"] == "A-B"

    def test_mvfilter_over_a_field_the_row_lacks_is_null(self) -> None:
        assert value('mvfilter(nosuchfield=="x")') is None

    def test_mvfilter_needs_a_field_to_bind(self) -> None:
        assert "The arguments to the 'mvfilter' function are invalid." in failure(
            "mvfilter(true())",
        )


class TestNullAndMissingFields:
    """A typed null, and a field the row does not have."""

    def test_a_missing_field_makes_the_call_null(self) -> None:
        assert value("upper(nosuchfield)") is None
        assert value("len(nosuchfield)") is None
        assert value('substr(nosuchfield,1,2)') is None

    def test_a_typed_null_is_an_argument_error(self) -> None:
        # The difference that matters: `upper(nosuchfield)` above is fine.
        assert "The arguments to the 'upper' function are invalid." in failure(
            "upper(null())",
        )
        assert "the 'mvcount' function are invalid." in failure("mvcount(null())")

    def test_the_functions_that_answer_about_a_value_see_it(self) -> None:
        assert value("typeof(nosuchfield)") == "Invalid"
        assert value("tostring(nosuchfield)") == "Null"
        assert value('printf("%s",nosuchfield)') == "Null"
        assert value("typeof(null())") == "Invalid"

    def test_assigning_null_drops_the_field(self) -> None:
        rows, _ = run('| makeresults | eval a="x", v=null() | table a, v')
        assert rows == [{"a": "x"}]

    def test_concatenating_a_missing_field_is_null(self) -> None:
        # Not "x": the whole expression is null.
        assert value('nosuchfield."x"') is None
        assert value('"x".nosuchfield') is None

    def test_an_empty_string_is_not_a_missing_field(self) -> None:
        rows, _ = run('| makeresults | eval a="" | eval v=a."x" | table v')
        assert rows[0]["v"] == "x"


class TestStaticTypeChecking:
    """What splunkd refuses before it reads a row."""

    def test_plus_takes_two_strings_or_two_numbers(self) -> None:
        assert failure('"1"+1') == (
            "Error in 'EvalCommand': Type checking failed. '+' only takes "
            "two strings or two numbers."
        )

    def test_two_strings_concatenate(self) -> None:
        assert value('"a"+"b"') == "ab"

    @pytest.mark.parametrize("op", ["-", "*", "/", "%"])
    def test_the_other_operators_only_take_numbers(self, op: str) -> None:
        assert failure(f'"a"{op}"b"') == (
            f"Error in 'EvalCommand': Type checking failed. '{op}' only takes numbers."
        )

    def test_concatenation_will_not_take_a_null(self) -> None:
        assert failure('"x".null()') == (
            "Error in 'EvalCommand': Type checking failed. The '.' operator "
            "only takes strings and numbers."
        )

    def test_a_comparison_against_a_null_is_refused(self) -> None:
        assert failure('if(null()=="","y","n")') == (
            "Error in 'EvalCommand': Type checking failed. The '==' operator "
            "received different types."
        )

    def test_a_field_is_typed_when_the_row_arrives(self) -> None:
        # None of these is a type error: the value decides.
        rows, _ = run('| makeresults | eval a="1" | eval v=a+1 | table v')
        assert rows[0]["v"] == 2
        rows, _ = run('| makeresults | eval a="x" | eval v=a+1 | table v')
        assert rows == []

    def test_a_string_operand_makes_plus_concatenate(self) -> None:
        rows, _ = run('| makeresults | eval a=1 | eval v=a+"2" | table v')
        assert rows[0]["v"] == "12"


class TestMinAndMax:
    """Ordering values of mixed type."""

    def test_a_string_ranks_above_every_number(self) -> None:
        assert value('max(1,"a",3)') == "a"
        assert value('min(3,"a")') == 3

    def test_quoted_numbers_compare_as_text(self) -> None:
        assert value('min("10","9")') == "10"

    def test_a_field_holding_a_number_compares_as_one(self) -> None:
        # Ordered as the number 10, and handed back as the value it was.
        rows, _ = run('| makeresults | eval a="10" | eval v=max(a,9) | table v')
        assert rows[0]["v"] == "10"

    def test_a_null_argument_takes_no_part(self) -> None:
        assert value('max("abc",null())') == "abc"
        assert value("min(null(),3)") == 3

    def test_no_arguments_at_all_is_an_error(self) -> None:
        assert "The arguments to the 'min' function are invalid." in failure("min()")


class TestJson:
    """``spath``, ``json_extract`` and the constructors."""

    def test_a_path_descends_objects_and_arrays(self) -> None:
        assert value(r'json_extract("{\"a\":{\"b\":[1,{\"c\":3}]}}","a.b{1}.c")') == 3

    def test_a_bare_brace_asks_for_the_array_itself(self) -> None:
        assert value(r'json_extract("{\"a\":[1,2]}","a{}")') == "[1,2]"

    def test_spath_reads_the_same_paths(self) -> None:
        assert value(r'spath("{\"a\":[1,2]}","a{1}")') == 2

    def test_text_that_is_not_json_assigns_nothing(self) -> None:
        assert value('json_extract("notjson","a")') is None
        assert value('spath("notjson","a")') is None

    def test_a_path_that_is_not_there_assigns_nothing(self) -> None:
        assert value(r'json_extract("{\"a\":1}","zz")') is None

    def test_the_constructors_write_compact_json(self) -> None:
        assert value('json_object("a",1,"b","x")') == '{"a":1,"b":"x"}'
        assert value('json_array("a",1)') == '["a",1]'

    def test_json_valid_answers_about_the_text(self) -> None:
        assert value(r'if(json_valid("[1]"),"y","n")') == "y"
        assert value('if(json_valid("nope"),"y","n")') == "n"


class TestValidateAndMaths:
    """``validate`` and the numeric corners."""

    def test_validate_answers_with_the_first_false_condition(self) -> None:
        assert value('validate(1==2,"a",1==2,"b")') == "a"
        assert value('validate(1==1,"a",1==2,"b")') == "b"

    def test_all_conditions_true_assigns_nothing(self) -> None:
        assert value('validate(1==1,"a")') is None

    def test_an_undefined_result_assigns_nothing(self) -> None:
        # `sqrt(-1)` is undefined rather than wrong, and is not an error.
        assert value("sqrt(-1)") is None
        assert value("ln(0)") is None
        assert value("1/0") is None

    def test_a_bad_argument_is_still_an_error(self) -> None:
        assert "the 'sqrt' function are invalid." in failure('sqrt("x")')

    def test_exact_keeps_every_digit(self) -> None:
        assert value("exact(1/3)") == pytest.approx(1 / 3)

    def test_sigfig_takes_one_argument(self) -> None:
        assert "the 'sigfig' function are invalid." in failure("sigfig(1.23456,3)")

    def test_random_stays_inside_the_range(self) -> None:
        assert value('if(random()>=0 AND random()<2147483648,"y","n")') == "y"


class TestMakeresults:
    """The command every Splunk example starts with."""

    def test_one_row_carrying_only_a_time(self) -> None:
        rows, _ = run("| makeresults")
        assert len(rows) == 1
        assert set(rows[0]) == {"_time"}

    def test_count_asks_for_more_rows(self) -> None:
        assert len(run("| makeresults count=3")[0]) == 3

    def test_count_zero_produces_none(self) -> None:
        assert run("| makeresults count=0")[0] == []

    def test_annotate_names_the_server(self) -> None:
        rows, _ = run("| makeresults annotate=true")
        assert rows[0]["splunk_server"] == "mockdr-splunk"

    @pytest.mark.parametrize("word", ["true", "t", "yes", "1", "TRUE"])
    def test_the_words_that_mean_true(self, word: str) -> None:
        assert "splunk_server" in run(f"| makeresults annotate={word}")[0][0]

    @pytest.mark.parametrize("word", ["false", "f", "no", "0"])
    def test_the_words_that_mean_false(self, word: str) -> None:
        assert "splunk_server" not in run(f"| makeresults annotate={word}")[0][0]

    @pytest.mark.parametrize("word", ["maybe", "on", "y", ""])
    def test_every_other_word_is_refused(self, word: str) -> None:
        _rows, messages = run(f"| makeresults annotate={word}")
        assert messages[0]["text"] == (
            "Error in 'SearchProcessor': Invalid option value. Expecting a "
            f"'boolean' for option 'annotate'. Instead got '{word}'."
        )

    @pytest.mark.parametrize("count", ["-1", "abc", "1.5", '" 2 "'])
    def test_count_must_be_a_non_negative_integer(self, count: str) -> None:
        _rows, messages = run(f"| makeresults count={count}")
        assert "Expecting a 'non-negative integer' for option 'count'." in (
            messages[0]["text"]
        )

    @pytest.mark.parametrize("count", ["+2", "02"])
    def test_the_forms_of_an_integer_splunkd_takes(self, count: str) -> None:
        assert len(run(f"| makeresults count={count}")[0]) == 2

    def test_an_option_is_not_given_twice(self) -> None:
        _rows, messages = run("| makeresults count=2 count=3")
        assert messages[0]["text"] == (
            "Error in 'SearchProcessor': Option 'count' should not be "
            "specified more than once."
        )

    def test_it_must_come_first(self) -> None:
        _rows, messages = run("| makeresults | eval v=1 | makeresults count=1")
        assert messages[0]["text"] == (
            "Error in 'makeresults' command: This command must be the first "
            "command of a search."
        )

    def test_an_unknown_argument_is_ignored(self) -> None:
        # splunkd takes it without complaint, and so does this.
        assert len(run("| makeresults nosucharg=1")[0]) == 1


class TestMakeresultsInlineData:
    """``format`` and ``data``, which read rows from the search text."""

    def test_csv_takes_its_field_names_from_the_header(self) -> None:
        rows, _ = run('| makeresults format=csv data="a,b\n1,2\n3,4"')
        # No `_time` at all: inline CSV rows carry only their own fields.
        assert rows == [{"a": "1", "b": "2"}, {"a": "3", "b": "4"}]

    def test_a_quoted_cell_keeps_its_comma(self) -> None:
        rows, _ = run('| makeresults format=csv data="a,b\n\\"x,y\\",2"')
        assert rows[0]["a"] == "x,y"

    def test_a_short_row_simply_lacks_those_fields(self) -> None:
        rows, _ = run('| makeresults format=csv data="a,b\n1"')
        assert rows == [{"a": "1"}]

    def test_cells_beyond_the_header_are_dropped(self) -> None:
        rows, _ = run('| makeresults format=csv data="a,b\n1,2,3"')
        assert rows == [{"a": "1", "b": "2"}]

    def test_a_header_with_nothing_under_it_produces_no_rows(self) -> None:
        assert run('| makeresults format=csv data="a"')[0] == []

    def test_json_keeps_each_object_as_raw(self) -> None:
        rows, _ = run(r'| makeresults format=json data="[{\"a\":1}]"')
        assert rows[0]["_raw"] == '{"a":1}'
        assert rows[0]["a"] == 1
        assert "_time" in rows[0]

    def test_a_nested_json_value_becomes_its_text(self) -> None:
        rows, _ = run(r'| makeresults format=json data="[{\"b\":[1,2]}]"')
        assert rows[0]["b"] == "[1,2]"

    def test_json_that_is_not_an_array_of_objects_is_refused(self) -> None:
        _rows, messages = run(r'| makeresults format=json data="{\"a\":1}"')
        # This is the one message splunkd sends with no subject in front.
        assert messages[0]["text"] == (
            "Incorrectly-formatted JSON data detected. Make sure your "
            "JSON-formatted data starts with '[' and ends with ']' and "
            "consists of JSON objects."
        )

    def test_text_that_is_not_json_produces_no_rows(self) -> None:
        assert run('| makeresults format=json data="notjson"')[0] == []

    @pytest.mark.parametrize("arg", ["format=csv", "data=x"])
    def test_the_two_arguments_go_together(self, arg: str) -> None:
        _rows, messages = run(f"| makeresults {arg}")
        assert messages[0]["text"].startswith(
            "Error in 'MakeResultsProcessor': You must specify both 'format' "
            "and 'data' arguments",
        )

    def test_inline_data_allows_no_other_argument(self) -> None:
        _rows, messages = run('| makeresults format=csv data="a\n1" count=5')
        assert messages[0]["text"].startswith(
            "Error in 'MakeResultsProcessor': When 'makeresults' generates "
            "events from inline data",
        )

    def test_only_csv_and_json_are_formats(self) -> None:
        _rows, messages = run('| makeresults format=xml data="<a/>"')
        assert messages[0]["text"] == (
            "Error in 'MakeResultsProcessor': An invalid 'format' was "
            "specified: xml. Valid 'format' options are 'csv' and 'json'."
        )
