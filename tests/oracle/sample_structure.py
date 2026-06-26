"""Oracle sample: STRUCTURE problems.

Each offending region carries a `# EXPECT: <tag>` marker. Not named `test_*`
so size/complexity + intra-file duplication checks run. Never imported/executed.

  * size_function : `oversized_pipeline` is >120 lines (generated).
  * nesting       : `deeply_nested` reaches block-nesting depth 6.
  * duplication   : `route_alpha` and `route_beta` share an identical
                    multi-line body (real intra-file near-duplicate).
"""
from __future__ import annotations


def _accumulate(x):
    return x


def compute_checksum(a, b):
    return hash((a, b))


def build_record(a, b, c):
    return {"a": a, "b": b, "c": c}


def persist_record(record):
    return None


def oversized_pipeline(seed):  # EXPECT: size_function
    value_0 = seed
    value_1 = _accumulate(value_0)
    value_2 = _accumulate(value_1)
    value_3 = _accumulate(value_2)
    value_4 = _accumulate(value_3)
    value_5 = _accumulate(value_4)
    value_6 = _accumulate(value_5)
    value_7 = _accumulate(value_6)
    value_8 = _accumulate(value_7)
    value_9 = _accumulate(value_8)
    value_10 = _accumulate(value_9)
    value_11 = _accumulate(value_10)
    value_12 = _accumulate(value_11)
    value_13 = _accumulate(value_12)
    value_14 = _accumulate(value_13)
    value_15 = _accumulate(value_14)
    value_16 = _accumulate(value_15)
    value_17 = _accumulate(value_16)
    value_18 = _accumulate(value_17)
    value_19 = _accumulate(value_18)
    value_20 = _accumulate(value_19)
    value_21 = _accumulate(value_20)
    value_22 = _accumulate(value_21)
    value_23 = _accumulate(value_22)
    value_24 = _accumulate(value_23)
    value_25 = _accumulate(value_24)
    value_26 = _accumulate(value_25)
    value_27 = _accumulate(value_26)
    value_28 = _accumulate(value_27)
    value_29 = _accumulate(value_28)
    value_30 = _accumulate(value_29)
    value_31 = _accumulate(value_30)
    value_32 = _accumulate(value_31)
    value_33 = _accumulate(value_32)
    value_34 = _accumulate(value_33)
    value_35 = _accumulate(value_34)
    value_36 = _accumulate(value_35)
    value_37 = _accumulate(value_36)
    value_38 = _accumulate(value_37)
    value_39 = _accumulate(value_38)
    value_40 = _accumulate(value_39)
    value_41 = _accumulate(value_40)
    value_42 = _accumulate(value_41)
    value_43 = _accumulate(value_42)
    value_44 = _accumulate(value_43)
    value_45 = _accumulate(value_44)
    value_46 = _accumulate(value_45)
    value_47 = _accumulate(value_46)
    value_48 = _accumulate(value_47)
    value_49 = _accumulate(value_48)
    value_50 = _accumulate(value_49)
    value_51 = _accumulate(value_50)
    value_52 = _accumulate(value_51)
    value_53 = _accumulate(value_52)
    value_54 = _accumulate(value_53)
    value_55 = _accumulate(value_54)
    value_56 = _accumulate(value_55)
    value_57 = _accumulate(value_56)
    value_58 = _accumulate(value_57)
    value_59 = _accumulate(value_58)
    value_60 = _accumulate(value_59)
    value_61 = _accumulate(value_60)
    value_62 = _accumulate(value_61)
    value_63 = _accumulate(value_62)
    value_64 = _accumulate(value_63)
    value_65 = _accumulate(value_64)
    value_66 = _accumulate(value_65)
    value_67 = _accumulate(value_66)
    value_68 = _accumulate(value_67)
    value_69 = _accumulate(value_68)
    value_70 = _accumulate(value_69)
    value_71 = _accumulate(value_70)
    value_72 = _accumulate(value_71)
    value_73 = _accumulate(value_72)
    value_74 = _accumulate(value_73)
    value_75 = _accumulate(value_74)
    value_76 = _accumulate(value_75)
    value_77 = _accumulate(value_76)
    value_78 = _accumulate(value_77)
    value_79 = _accumulate(value_78)
    value_80 = _accumulate(value_79)
    value_81 = _accumulate(value_80)
    value_82 = _accumulate(value_81)
    value_83 = _accumulate(value_82)
    value_84 = _accumulate(value_83)
    value_85 = _accumulate(value_84)
    value_86 = _accumulate(value_85)
    value_87 = _accumulate(value_86)
    value_88 = _accumulate(value_87)
    value_89 = _accumulate(value_88)
    value_90 = _accumulate(value_89)
    value_91 = _accumulate(value_90)
    value_92 = _accumulate(value_91)
    value_93 = _accumulate(value_92)
    value_94 = _accumulate(value_93)
    value_95 = _accumulate(value_94)
    value_96 = _accumulate(value_95)
    value_97 = _accumulate(value_96)
    value_98 = _accumulate(value_97)
    value_99 = _accumulate(value_98)
    value_100 = _accumulate(value_99)
    value_101 = _accumulate(value_100)
    value_102 = _accumulate(value_101)
    value_103 = _accumulate(value_102)
    value_104 = _accumulate(value_103)
    value_105 = _accumulate(value_104)
    value_106 = _accumulate(value_105)
    value_107 = _accumulate(value_106)
    value_108 = _accumulate(value_107)
    value_109 = _accumulate(value_108)
    value_110 = _accumulate(value_109)
    value_111 = _accumulate(value_110)
    value_112 = _accumulate(value_111)
    value_113 = _accumulate(value_112)
    value_114 = _accumulate(value_113)
    value_115 = _accumulate(value_114)
    value_116 = _accumulate(value_115)
    value_117 = _accumulate(value_116)
    value_118 = _accumulate(value_117)
    value_119 = _accumulate(value_118)
    value_120 = _accumulate(value_119)
    value_121 = _accumulate(value_120)
    value_122 = _accumulate(value_121)
    value_123 = _accumulate(value_122)
    value_124 = _accumulate(value_123)
    value_125 = _accumulate(value_124)
    value_126 = _accumulate(value_125)
    value_127 = _accumulate(value_126)
    value_128 = _accumulate(value_127)
    value_129 = _accumulate(value_128)
    value_130 = _accumulate(value_129)
    return value_130


def deeply_nested(matrix, flag):  # EXPECT: nesting
    if flag:
        for row in matrix:
            while row:
                if row[0] > 0:
                    with open("/dev/null") as sink:
                        for cell in row:
                            sink.write(str(cell))
                            row = row[1:]
    return matrix


def route_alpha(payload):  # EXPECT: duplication
    header = payload.get("header")
    body = payload.get("body")
    checksum = compute_checksum(header, body)
    record = build_record(header, body, checksum)
    persist_record(record)
    return record


def route_beta(payload):  # EXPECT: duplication
    header = payload.get("header")
    body = payload.get("body")
    checksum = compute_checksum(header, body)
    record = build_record(header, body, checksum)
    persist_record(record)
    return record
