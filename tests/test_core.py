import csv
import io

import pytest

from opentask.core import (
    ProcessRow,
    counter_rate,
    human_bytes,
    identity_matches,
    processes_csv,
    spreadsheet_safe,
)


@pytest.mark.parametrize(('value', 'expected'), [(0, '0.0 Б'), (-10, '0.0 Б'),
                                                 (1024, '1.0 КиБ'), (1024**3, '1.0 ГиБ')])
def test_human_bytes(value, expected):
    assert human_bytes(value) == expected


@pytest.mark.parametrize(('current', 'old', 'elapsed', 'expected'),
                         [(300, 100, 2, 100), (50, 100, 1, 0), (100, 0, 0, 0), (100, 0, -1, 0)])
def test_counter_rate(current, old, elapsed, expected):
    assert counter_rate(current, old, elapsed) == expected


def test_identity():
    assert identity_matches(100.12345, 100.12345)
    assert not identity_matches(100, 101)


@pytest.mark.parametrize('value', ['=1+1', '+CMD', '-1+1', '@SUM(A1)', '  =1', '\t=1', '\n@X'])
def test_csv_formula_escape(value):
    assert spreadsheet_safe(value).startswith("'")


def test_csv_roundtrip():
    row = ProcessRow(123, 1, '=cmd,тест', 'user', 2.25, 4096, 3, 'running', 1000)
    data = list(csv.reader(io.StringIO(processes_csv([row]))))
    assert data[1][0] == '123'
    assert data[1][2] == "'=cmd,тест"
    assert data[1][4] == '2.25'
    assert len(data[1]) == len(data[0]) == 9
