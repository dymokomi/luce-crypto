#!/usr/bin/env python3
"""Generate/check public fixtures with pinned test-only reference Argon2, never runtime."""
import argparse
from importlib.metadata import version
import json
from pathlib import Path
import random

VERSIONS = {"argon2-cffi": "25.1.0", "argon2-cffi-bindings": "25.1.0", "cffi": "2.0.0", "pycparser": "3.0"}
FIXTURE = Path(__file__).resolve().parent / "vectors/argon2id.json"


def reference(case, threads=1):
    from argon2.low_level import Type, core, ffi, lib
    fields = [bytes.fromhex(case[name]) for name in ("password", "salt", "key", "associated")]
    buffers = [ffi.new("uint8_t[]", field) for field in fields]
    output = ffi.new("uint8_t[]", case["length"])
    context = ffi.new("argon2_context *", dict(
        out=output, outlen=case["length"], pwd=buffers[0], pwdlen=len(fields[0]),
        salt=buffers[1], saltlen=len(fields[1]), secret=buffers[2], secretlen=len(fields[2]),
        ad=buffers[3], adlen=len(fields[3]), t_cost=case["passes"], m_cost=case["memory_kib"],
        lanes=case["lanes"], threads=threads, version=19, allocate_cbk=ffi.NULL,
        free_cbk=ffi.NULL, flags=lib.ARGON2_DEFAULT_FLAGS))
    result = core(context, Type.ID.value)
    if result != lib.ARGON2_OK:
        raise AssertionError(f"reference failed: {result}")
    return bytes(ffi.buffer(output, case["length"])).hex()


def inputs():
    yield dict(group="rfc9106", memory_kib=32, passes=3, lanes=4, length=32,
               password=(b"\x01" * 32).hex(), salt=(b"\x02" * 16).hex(),
               key=(b"\x03" * 8).hex(), associated=(b"\x04" * 12).hex())
    rng = random.Random(910613)
    def case(memory, passes, lanes, length, group="quick", sizes=(32, 16, 8, 12)):
        return dict(group=group, memory_kib=memory, passes=passes, lanes=lanes, length=length,
                    **{name: rng.randbytes(size).hex() for name, size in zip(("password", "salt", "key", "associated"), sizes)})
    for lanes in (1, 2, 3, 4, 7, 8, 17, 64):
        for delta in (0, 1, 4 * lanes - 1, 4 * lanes):
            for passes in (1, 2, 3):
                yield case(8 * lanes + delta, passes, lanes, 32)
    # Address-block transitions at segment offsets 127/128/129/256/257.
    for lanes in (1, 3, 4):
        for segment in (127, 128, 129, 256, 257):
            yield case(4 * lanes * segment, 2, lanes, 32)
    for length in (4, 16, 31, 32, 33, 63, 64, 65, 95, 96, 97, 128, 1024, 65536):
        yield case(32, 3, 4, length)
    for size in (0, 1, 63, 64, 65, 127, 128, 129, 1024, 65536):
        yield case(32, 2, 2, 32, sizes=(size, 8 if size % 2 else 17, size, size))
    yield case(65536, 3, 4, 32, "extended")
    yield case(262144, 1, 4, 32, "extended")


def document():
    for package, expected in VERSIONS.items():
        assert version(package) == expected, (package, version(package), expected)
    cases = []
    for index, case in enumerate(inputs()):
        expected = reference(case)
        assert reference(case, min(case["lanes"], 8)) == expected
        if index == 0:
            assert expected == "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        cases.append(dict(id=index, **case, expected=expected))
    return dict(format="luce-crypto-argon2id-v1", version=19, oracle=VERSIONS, cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="explicitly regenerate the public fixture")
    args = parser.parse_args()
    encoded = (json.dumps(document(), indent=2, sort_keys=True) + "\n").encode()
    if args.write:
        FIXTURE.write_bytes(encoded)
    else:
        assert FIXTURE.read_bytes() == encoded, "committed fixture differs from pinned independent reference"
    print(f"PASS reference Argon2id fixture: {len(list(inputs()))} cases, serial and parallel reference agree", flush=True)


if __name__ == "__main__":
    main()
