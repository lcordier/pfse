from datasource import BasicSource


def test_mod_elements():
    assert BasicSource([0, 1, 255, 256, 257]) == BasicSource([0, 1, 255, 0, 1])


def test_mod_size():
    data = BasicSource([1, 2, 3])
    assert [data[i] for i in range(7)] == [1, 2, 3, 1, 2, 3, 1]
