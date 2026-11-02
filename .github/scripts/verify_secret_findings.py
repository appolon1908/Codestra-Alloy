"""Classify only independently verified immutable public Alloy fixtures.
All scans remain complete; unknown identities, contents and scanner errors fail.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

# Scope,path,commit,rule,start,end,fingerprint -> exact immutable file and range.
# Reviewed provenance: docs/PUBLIC-FIXTURE-PROVENANCE.md.
REVIEWED_COMMITS = ['', '104966b2cac822d2cc61f058e53a9dff4a10e03e', '8b6f55998d8034aa768bbb6f7a1064952a639075']

REVIEWED_PROOFS = [
    {
        "blob": "fcff83e1cdc00d699039b77dad70fa581764c78e",
        "line_sha256": "bae4bc36e6b3b7abdaa2f459010e4e0bbef57c5d8edbb65e3261459ebde9166e",
        "maximum": 1,
        "mode": "100644",
        "sha256": "f159023876a9eca8525f32df24e04e7157bcc650ea758ce29604e903aa0dafac"
    },
    {
        "blob": "fcff83e1cdc00d699039b77dad70fa581764c78e",
        "line_sha256": "97d97afae3d9cbb0164ce11052e3546eed96fb20a8121900011b3bdf56d31b00",
        "maximum": 2,
        "mode": "100644",
        "sha256": "f159023876a9eca8525f32df24e04e7157bcc650ea758ce29604e903aa0dafac"
    },
    {
        "blob": "cebdb760441a814503c740423990a60b05d7751b",
        "line_sha256": "ac3357bedd2a9b79ab6a178e85d15d2108257f4b4fa33151f9e61c6099aff601",
        "maximum": 1,
        "mode": "100644",
        "sha256": "394ec8ce3a2f72a9ff881107efede91d93d714659d285accdaa8ab8b7d9ebe9b"
    },
    {
        "blob": "fbf411b5b333582ae352964aebfd8f86ddaba33c",
        "line_sha256": "3aea406fe443fb823a4b8e3681eabd8e794ee0dc372e97307ceef35139e1bd6e",
        "maximum": 1,
        "mode": "100644",
        "sha256": "e6a80d7c9591eee83f94ccf24078f2cf1316df227f87f84a454e99936361bcc6"
    },
    {
        "blob": "18924109da327176ed5442b214af5af0f28b7eea",
        "line_sha256": "6964788a0f9a189280b446f8a50d49b2f674862b3065c673e88bf923cd0b496b",
        "maximum": 1,
        "mode": "100644",
        "sha256": "8de231f305a75354bb1676bec162c8147417e96696cc9d1bd2ced69fe4888092"
    },
    {
        "blob": "18924109da327176ed5442b214af5af0f28b7eea",
        "line_sha256": "1ca302d938ee31d694dec48e0dc2139806cf8a2e5b4318c1d853988da93d43c5",
        "maximum": 1,
        "mode": "100644",
        "sha256": "8de231f305a75354bb1676bec162c8147417e96696cc9d1bd2ced69fe4888092"
    },
    {
        "blob": "8a1bb8592c91763144af5164c1e1387c79f70bcf",
        "line_sha256": "c55a64a404f61c80d2d4be985fe135b165705c231e4d304ca53d4ffb38aee541",
        "maximum": 1,
        "mode": "100644",
        "sha256": "eaa8197bca6adc97869b8bdbc56d2c432bb181e545b63174125992e903ba3fc8"
    },
    {
        "blob": "8a1bb8592c91763144af5164c1e1387c79f70bcf",
        "line_sha256": "2a42c2132d4ecfeeaa79a3b78e76094b1d2e1a80025a73e304bb197f6225bfe0",
        "maximum": 1,
        "mode": "100644",
        "sha256": "eaa8197bca6adc97869b8bdbc56d2c432bb181e545b63174125992e903ba3fc8"
    },
    {
        "blob": "faf0799ab313c291bce97b2f15993aeb1d9f4937",
        "line_sha256": "8d7d55a2b123f109aba31c82a799e3f4fee17be31c242ecb96df0d634c64f594",
        "maximum": 1,
        "mode": "100644",
        "sha256": "03fb06446b7a1652518a24d460f3ba881fe25a905b35e0e8daf36d0c70dc97ae"
    },
    {
        "blob": "faf0799ab313c291bce97b2f15993aeb1d9f4937",
        "line_sha256": "b2221332ca4c0558d5c685ac86c4315f6eb9a2c51dbe91e9052c0cc993751ce7",
        "maximum": 1,
        "mode": "100644",
        "sha256": "03fb06446b7a1652518a24d460f3ba881fe25a905b35e0e8daf36d0c70dc97ae"
    },
    {
        "blob": "acc0a7fabdc6cca27ccb95e0c106b05c59ffb70c",
        "line_sha256": "8bcac7908eb950419537b91e19adc83ce2c9cbfdacf4f81157fdadfec11f7017",
        "maximum": 1,
        "mode": "100644",
        "sha256": "84266d00f9ccd8f6c27c3e4d8d8604fb55449ca2c935f075ab3ec828df90a716"
    },
    {
        "blob": "db63c88e5e64a61d778e4b067dd5b0ddecc13076",
        "line_sha256": "a3f66e0289f986aee7f5f47d4af119773b4738fe27f33445619cd2441e63a474",
        "maximum": 1,
        "mode": "100644",
        "sha256": "01a9accc4506c0740551a4adca1105dff03afe60b0ab51903631a8405e6bfbae"
    },
    {
        "blob": "db63c88e5e64a61d778e4b067dd5b0ddecc13076",
        "line_sha256": "e5ff60b47111d82c6a3c45c88654aed7320928944c68a6900a3762f659d46b87",
        "maximum": 1,
        "mode": "100644",
        "sha256": "01a9accc4506c0740551a4adca1105dff03afe60b0ab51903631a8405e6bfbae"
    },
    {
        "blob": "db63c88e5e64a61d778e4b067dd5b0ddecc13076",
        "line_sha256": "a28136fefebd4f7ae0c0f6562568130ca3d3cd9971b517456827b19058ccba81",
        "maximum": 1,
        "mode": "100644",
        "sha256": "01a9accc4506c0740551a4adca1105dff03afe60b0ab51903631a8405e6bfbae"
    },
    {
        "blob": "456c5145e2674e2ba8e7e3e237ef63306cff79e2",
        "line_sha256": "89d48f6c0840a25b7da6d9fe8ce5b9c43041e53007aa0fbca1acb115e96f80f6",
        "maximum": 1,
        "mode": "100644",
        "sha256": "a6f030c84f9dcb0c996cb8dbe6ed0b8351b406b0db5c12d41b68596ffa3a6c76"
    },
    {
        "blob": "456c5145e2674e2ba8e7e3e237ef63306cff79e2",
        "line_sha256": "89d48f6c0840a25b7da6d9fe8ce5b9c43041e53007aa0fbca1acb115e96f80f6",
        "maximum": 1,
        "mode": "100644",
        "sha256": "a6f030c84f9dcb0c996cb8dbe6ed0b8351b406b0db5c12d41b68596ffa3a6c76"
    },
    {
        "blob": "456c5145e2674e2ba8e7e3e237ef63306cff79e2",
        "line_sha256": "89d48f6c0840a25b7da6d9fe8ce5b9c43041e53007aa0fbca1acb115e96f80f6",
        "maximum": 1,
        "mode": "100644",
        "sha256": "a6f030c84f9dcb0c996cb8dbe6ed0b8351b406b0db5c12d41b68596ffa3a6c76"
    },
    {
        "blob": "56820979b0b4462dd12963d611a4da3c9176fa6c",
        "line_sha256": "b223b0bb1d0091b25fdd0bdcf80d4b44bc23e1d514cb230f76956824bf8b8c71",
        "maximum": 1,
        "mode": "100644",
        "sha256": "ed32593d2a92ec59abf921307df0abbab1bdcfb1a34b774e4b91faec94521162"
    },
    {
        "blob": "56820979b0b4462dd12963d611a4da3c9176fa6c",
        "line_sha256": "3b6cb310ccea3cd03a15c71dc20049fd56bf08c9ab254cc2e1699dba9b5060da",
        "maximum": 1,
        "mode": "100644",
        "sha256": "ed32593d2a92ec59abf921307df0abbab1bdcfb1a34b774e4b91faec94521162"
    },
    {
        "blob": "56820979b0b4462dd12963d611a4da3c9176fa6c",
        "line_sha256": "87c3ff8f0f1672421b05d7d2d55f2744d5671b6df30d64b36e2caf424bf7a8ee",
        "maximum": 1,
        "mode": "100644",
        "sha256": "ed32593d2a92ec59abf921307df0abbab1bdcfb1a34b774e4b91faec94521162"
    },
    {
        "blob": "c8ac9e293c45154e913c14c13f26bf4d3850f198",
        "line_sha256": "f077b23f2d0f12dab4c5f29717ae754df23a936dbc44f5732d430d4f5e20f7cf",
        "maximum": 1,
        "mode": "100644",
        "sha256": "e166980ecfdb9fabc442401ba18edf9cc457c16746afb42131719b1e9215af88"
    },
    {
        "blob": "94ccd91a76689103521a322991456f7d8bdc8a7c",
        "line_sha256": "dd7b93056422ae5c4c9ff00b8ede5ad6a56d7756ec6bbd12c8c2d792121d8ee7",
        "maximum": 1,
        "mode": "100644",
        "sha256": "99b4f463bcf5a5cac596eeae1bc52fb2cf9fa8c93d3cfea5a21db7f43a029ce5"
    },
    {
        "blob": "fdbb0ba5b04468eeb5d4317d0bb9aa99901e3b43",
        "line_sha256": "1e5c5d9f1d42ee475917265feaa58883afd7e5c943a24246b0469d8b9439732a",
        "maximum": 1,
        "mode": "100644",
        "sha256": "bb44f7a4ea3671f8874e5a43e609370604f911cc004bd728d52c7f8912e45161"
    },
    {
        "blob": "20d68d6cc0e40d6deeeab069900b3e34399ffdd3",
        "line_sha256": "a8ca6a224fd089633161b7744087c1069072a0b7e21aeda2944a004b59c66c7c",
        "maximum": 1,
        "mode": "100644",
        "sha256": "720de71f0090c69b9536e614fde62b4e8d2d3bfc0364a50da2edaed15e065c04"
    },
    {
        "blob": "7c2d10f23f3ba63e89ae36823cc9e97d32250da1",
        "line_sha256": "9f97e89c1b0608c6ea3ecbaa75281130437cf0757f855c023e834acd9a042fc4",
        "maximum": 1,
        "mode": "100644",
        "sha256": "d3bdb695cbfec0ac35e909cfe1ff74a1c3ada5b2cf52654858943ea0864edcbb"
    },
    {
        "blob": "c2d4b7af95157b9673702ae3d14ce78f231e7f8e",
        "line_sha256": "dea9f61efc155a5b6bf870d7fcd3913de01ecce0c6a5deed8faa37aaf3be478d",
        "maximum": 1,
        "mode": "100644",
        "sha256": "35c0089351d5ba65ff3d466010e70ffaf44049f1ae4e9916a54fa0b3f4573dc6"
    },
    {
        "blob": "8be1dc127d7a2d052595f61d972f897e0783a5c4",
        "line_sha256": "53fbb93580c9ddb761dedfee4f8019fb13f339671b9e9f7eb74b51c2a8ade039",
        "maximum": 1,
        "mode": "100644",
        "sha256": "3b9a3a81722ccf7efcbae1c5ef5e7d768ad9f2558bd6bd9790833688bb8a4a44"
    },
    {
        "blob": "0c4dd9dbd9def05f3539df7f30ac426bf17901c6",
        "line_sha256": "9f97e89c1b0608c6ea3ecbaa75281130437cf0757f855c023e834acd9a042fc4",
        "maximum": 1,
        "mode": "100644",
        "sha256": "72727989f29ebbb1046fd6e777c252af29124eb02dce543108a760974f6318cc"
    },
    {
        "blob": "6896eb742d7e1a2f60297ee94e4885f54a63de68",
        "line_sha256": "e0ed194d8e0c5928a0464766bf00bf726ff2b125b74285bc59d074e9b16fb5f4",
        "maximum": 1,
        "mode": "100644",
        "sha256": "7da30283af794096248f3c997b6b5c14aa859ce6a5bf25015d88637ae2a146b6"
    },
    {
        "blob": "695e7a97b66612e7e6f8c4bb1d5c93986a925394",
        "line_sha256": "20e9081343af96f10be573b3b9629b7c6c9cba80c8805cf9c9016b309ec076c2",
        "maximum": 1,
        "mode": "100644",
        "sha256": "091f4a0e47d7f8c0fa927ee0f390806fe4de94a2c1020f83a8cec88ca76b6c30"
    },
    {
        "blob": "695e7a97b66612e7e6f8c4bb1d5c93986a925394",
        "line_sha256": "c15478d7ebd436b6d5420e6ebc39d10ef783fa65851793aa833ba2944ed088af",
        "maximum": 1,
        "mode": "100644",
        "sha256": "091f4a0e47d7f8c0fa927ee0f390806fe4de94a2c1020f83a8cec88ca76b6c30"
    },
    {
        "blob": "695e7a97b66612e7e6f8c4bb1d5c93986a925394",
        "line_sha256": "1aefdb1fccef0fb1c0aec8515d75d82c4436a3661b11bc988216058f444cef5f",
        "maximum": 1,
        "mode": "100644",
        "sha256": "091f4a0e47d7f8c0fa927ee0f390806fe4de94a2c1020f83a8cec88ca76b6c30"
    },
    {
        "blob": "695e7a97b66612e7e6f8c4bb1d5c93986a925394",
        "line_sha256": "a0e942c90a3c6f1935e4f1e9b39e0c3a13d01736ccf19080f6ddbb92eb02f011",
        "maximum": 1,
        "mode": "100644",
        "sha256": "091f4a0e47d7f8c0fa927ee0f390806fe4de94a2c1020f83a8cec88ca76b6c30"
    },
    {
        "blob": "695e7a97b66612e7e6f8c4bb1d5c93986a925394",
        "line_sha256": "5f111faab307e9dfbe34b7cfab5c9e7e010e93aefd41feae7d450cce1b886aa2",
        "maximum": 1,
        "mode": "100644",
        "sha256": "091f4a0e47d7f8c0fa927ee0f390806fe4de94a2c1020f83a8cec88ca76b6c30"
    },
    {
        "blob": "695e7a97b66612e7e6f8c4bb1d5c93986a925394",
        "line_sha256": "8e543c85888e398c2e7a99aae3e832ffdff824188f2c54f985129336209b8ac9",
        "maximum": 1,
        "mode": "100644",
        "sha256": "091f4a0e47d7f8c0fa927ee0f390806fe4de94a2c1020f83a8cec88ca76b6c30"
    },
    {
        "blob": "695e7a97b66612e7e6f8c4bb1d5c93986a925394",
        "line_sha256": "e132e006c127061559db0f0ff1eace5508981c3c829a91c20b19e54ef473eedd",
        "maximum": 1,
        "mode": "100644",
        "sha256": "091f4a0e47d7f8c0fa927ee0f390806fe4de94a2c1020f83a8cec88ca76b6c30"
    },
    {
        "blob": "695e7a97b66612e7e6f8c4bb1d5c93986a925394",
        "line_sha256": "14c8b000fb1c1fa5aa142ed451bffb950af7b915430d7656d6e11ca322fda649",
        "maximum": 1,
        "mode": "100644",
        "sha256": "091f4a0e47d7f8c0fa927ee0f390806fe4de94a2c1020f83a8cec88ca76b6c30"
    },
    {
        "blob": "695e7a97b66612e7e6f8c4bb1d5c93986a925394",
        "line_sha256": "7cb91e334a26a147198df12b2bf2dc59dcb7ca815ac570d4638503dab75d7801",
        "maximum": 1,
        "mode": "100644",
        "sha256": "091f4a0e47d7f8c0fa927ee0f390806fe4de94a2c1020f83a8cec88ca76b6c30"
    },
    {
        "blob": "695e7a97b66612e7e6f8c4bb1d5c93986a925394",
        "line_sha256": "abf756641cfb99063d7ee8317f97f0c0ac7f3515ed4a2b8331bde9e06ec60ab0",
        "maximum": 1,
        "mode": "100644",
        "sha256": "091f4a0e47d7f8c0fa927ee0f390806fe4de94a2c1020f83a8cec88ca76b6c30"
    },
    {
        "blob": "3e78e281e610d58af0cc4e703c57898c8051fa54",
        "line_sha256": "a880b75ee837109d0a167a73fdb623309570619f7f100c00cd0587509fa26408",
        "maximum": 1,
        "mode": "100644",
        "sha256": "43dc8fb4a77618f3ced34e569a05e71eeb01d0b0600dd1832819736060a396ca"
    },
    {
        "blob": "f01a0a1bd9b01dc7c9ba27eb2146d682358e763f",
        "line_sha256": "99986014c0b3376d58862f24d6ce32867e475533a4abcd4fef7e129277203ccb",
        "maximum": 1,
        "mode": "100644",
        "sha256": "50fa7b0ffc0ca64f93d72924872c2a1742e4dc2ad4ab0cc4051bfed41b4d85f5"
    },
    {
        "blob": "8be1dc127d7a2d052595f61d972f897e0783a5c4",
        "line_sha256": "53fbb93580c9ddb761dedfee4f8019fb13f339671b9e9f7eb74b51c2a8ade039",
        "maximum": 1,
        "mode": "100644",
        "sha256": "3b9a3a81722ccf7efcbae1c5ef5e7d768ad9f2558bd6bd9790833688bb8a4a44"
    },
    {
        "blob": "70fbb595ea5648cb85dc8e11ecc725838b4fe373",
        "line_sha256": "25bd5c6548d84a863cf353e981ae38509d44c9d891b704975ab8c8446a9f8093",
        "maximum": 1,
        "mode": "100644",
        "sha256": "2d2b71b0869259d8f5d108017cdf4b60e827eaf11d7c9102c092fe9208c784a6"
    },
    {
        "blob": "8bc6083d2f2febce67451c22a6de141c0f6aa932",
        "line_sha256": "4082264074525d35c5023a970163aa5e67941dc8b1db1d4dd471f5883696618a",
        "maximum": 1,
        "mode": "100644",
        "sha256": "28138d78096dc9045e15249b8cb82b6cc4b8df9e882d29828d0b13c00e269aef"
    },
    {
        "blob": "cebdb760441a814503c740423990a60b05d7751b",
        "line_sha256": "ac3357bedd2a9b79ab6a178e85d15d2108257f4b4fa33151f9e61c6099aff601",
        "maximum": 1,
        "mode": "100644",
        "sha256": "394ec8ce3a2f72a9ff881107efede91d93d714659d285accdaa8ab8b7d9ebe9b"
    },
    {
        "blob": "fbf411b5b333582ae352964aebfd8f86ddaba33c",
        "line_sha256": "3aea406fe443fb823a4b8e3681eabd8e794ee0dc372e97307ceef35139e1bd6e",
        "maximum": 1,
        "mode": "100644",
        "sha256": "e6a80d7c9591eee83f94ccf24078f2cf1316df227f87f84a454e99936361bcc6"
    },
    {
        "blob": "18924109da327176ed5442b214af5af0f28b7eea",
        "line_sha256": "6964788a0f9a189280b446f8a50d49b2f674862b3065c673e88bf923cd0b496b",
        "maximum": 1,
        "mode": "100644",
        "sha256": "8de231f305a75354bb1676bec162c8147417e96696cc9d1bd2ced69fe4888092"
    },
    {
        "blob": "18924109da327176ed5442b214af5af0f28b7eea",
        "line_sha256": "1ca302d938ee31d694dec48e0dc2139806cf8a2e5b4318c1d853988da93d43c5",
        "maximum": 1,
        "mode": "100644",
        "sha256": "8de231f305a75354bb1676bec162c8147417e96696cc9d1bd2ced69fe4888092"
    },
    {
        "blob": "8a1bb8592c91763144af5164c1e1387c79f70bcf",
        "line_sha256": "c55a64a404f61c80d2d4be985fe135b165705c231e4d304ca53d4ffb38aee541",
        "maximum": 1,
        "mode": "100644",
        "sha256": "eaa8197bca6adc97869b8bdbc56d2c432bb181e545b63174125992e903ba3fc8"
    },
    {
        "blob": "8a1bb8592c91763144af5164c1e1387c79f70bcf",
        "line_sha256": "2a42c2132d4ecfeeaa79a3b78e76094b1d2e1a80025a73e304bb197f6225bfe0",
        "maximum": 1,
        "mode": "100644",
        "sha256": "eaa8197bca6adc97869b8bdbc56d2c432bb181e545b63174125992e903ba3fc8"
    },
    {
        "blob": "faf0799ab313c291bce97b2f15993aeb1d9f4937",
        "line_sha256": "8d7d55a2b123f109aba31c82a799e3f4fee17be31c242ecb96df0d634c64f594",
        "maximum": 1,
        "mode": "100644",
        "sha256": "03fb06446b7a1652518a24d460f3ba881fe25a905b35e0e8daf36d0c70dc97ae"
    },
    {
        "blob": "faf0799ab313c291bce97b2f15993aeb1d9f4937",
        "line_sha256": "b2221332ca4c0558d5c685ac86c4315f6eb9a2c51dbe91e9052c0cc993751ce7",
        "maximum": 1,
        "mode": "100644",
        "sha256": "03fb06446b7a1652518a24d460f3ba881fe25a905b35e0e8daf36d0c70dc97ae"
    },
    {
        "blob": "acc0a7fabdc6cca27ccb95e0c106b05c59ffb70c",
        "line_sha256": "8bcac7908eb950419537b91e19adc83ce2c9cbfdacf4f81157fdadfec11f7017",
        "maximum": 1,
        "mode": "100644",
        "sha256": "84266d00f9ccd8f6c27c3e4d8d8604fb55449ca2c935f075ab3ec828df90a716"
    },
    {
        "blob": "db63c88e5e64a61d778e4b067dd5b0ddecc13076",
        "line_sha256": "a3f66e0289f986aee7f5f47d4af119773b4738fe27f33445619cd2441e63a474",
        "maximum": 1,
        "mode": "100644",
        "sha256": "01a9accc4506c0740551a4adca1105dff03afe60b0ab51903631a8405e6bfbae"
    },
    {
        "blob": "db63c88e5e64a61d778e4b067dd5b0ddecc13076",
        "line_sha256": "e5ff60b47111d82c6a3c45c88654aed7320928944c68a6900a3762f659d46b87",
        "maximum": 1,
        "mode": "100644",
        "sha256": "01a9accc4506c0740551a4adca1105dff03afe60b0ab51903631a8405e6bfbae"
    },
    {
        "blob": "db63c88e5e64a61d778e4b067dd5b0ddecc13076",
        "line_sha256": "a28136fefebd4f7ae0c0f6562568130ca3d3cd9971b517456827b19058ccba81",
        "maximum": 1,
        "mode": "100644",
        "sha256": "01a9accc4506c0740551a4adca1105dff03afe60b0ab51903631a8405e6bfbae"
    },
    {
        "blob": "456c5145e2674e2ba8e7e3e237ef63306cff79e2",
        "line_sha256": "89d48f6c0840a25b7da6d9fe8ce5b9c43041e53007aa0fbca1acb115e96f80f6",
        "maximum": 1,
        "mode": "100644",
        "sha256": "a6f030c84f9dcb0c996cb8dbe6ed0b8351b406b0db5c12d41b68596ffa3a6c76"
    },
    {
        "blob": "456c5145e2674e2ba8e7e3e237ef63306cff79e2",
        "line_sha256": "89d48f6c0840a25b7da6d9fe8ce5b9c43041e53007aa0fbca1acb115e96f80f6",
        "maximum": 1,
        "mode": "100644",
        "sha256": "a6f030c84f9dcb0c996cb8dbe6ed0b8351b406b0db5c12d41b68596ffa3a6c76"
    },
    {
        "blob": "456c5145e2674e2ba8e7e3e237ef63306cff79e2",
        "line_sha256": "89d48f6c0840a25b7da6d9fe8ce5b9c43041e53007aa0fbca1acb115e96f80f6",
        "maximum": 1,
        "mode": "100644",
        "sha256": "a6f030c84f9dcb0c996cb8dbe6ed0b8351b406b0db5c12d41b68596ffa3a6c76"
    },
    {
        "blob": "56820979b0b4462dd12963d611a4da3c9176fa6c",
        "line_sha256": "b223b0bb1d0091b25fdd0bdcf80d4b44bc23e1d514cb230f76956824bf8b8c71",
        "maximum": 1,
        "mode": "100644",
        "sha256": "ed32593d2a92ec59abf921307df0abbab1bdcfb1a34b774e4b91faec94521162"
    },
    {
        "blob": "56820979b0b4462dd12963d611a4da3c9176fa6c",
        "line_sha256": "3b6cb310ccea3cd03a15c71dc20049fd56bf08c9ab254cc2e1699dba9b5060da",
        "maximum": 1,
        "mode": "100644",
        "sha256": "ed32593d2a92ec59abf921307df0abbab1bdcfb1a34b774e4b91faec94521162"
    },
    {
        "blob": "56820979b0b4462dd12963d611a4da3c9176fa6c",
        "line_sha256": "87c3ff8f0f1672421b05d7d2d55f2744d5671b6df30d64b36e2caf424bf7a8ee",
        "maximum": 1,
        "mode": "100644",
        "sha256": "ed32593d2a92ec59abf921307df0abbab1bdcfb1a34b774e4b91faec94521162"
    },
    {
        "blob": "c8ac9e293c45154e913c14c13f26bf4d3850f198",
        "line_sha256": "f077b23f2d0f12dab4c5f29717ae754df23a936dbc44f5732d430d4f5e20f7cf",
        "maximum": 1,
        "mode": "100644",
        "sha256": "e166980ecfdb9fabc442401ba18edf9cc457c16746afb42131719b1e9215af88"
    },
    {
        "blob": "94ccd91a76689103521a322991456f7d8bdc8a7c",
        "line_sha256": "dd7b93056422ae5c4c9ff00b8ede5ad6a56d7756ec6bbd12c8c2d792121d8ee7",
        "maximum": 1,
        "mode": "100644",
        "sha256": "99b4f463bcf5a5cac596eeae1bc52fb2cf9fa8c93d3cfea5a21db7f43a029ce5"
    },
    {
        "blob": "fdbb0ba5b04468eeb5d4317d0bb9aa99901e3b43",
        "line_sha256": "1e5c5d9f1d42ee475917265feaa58883afd7e5c943a24246b0469d8b9439732a",
        "maximum": 1,
        "mode": "100644",
        "sha256": "bb44f7a4ea3671f8874e5a43e609370604f911cc004bd728d52c7f8912e45161"
    },
    {
        "blob": "20d68d6cc0e40d6deeeab069900b3e34399ffdd3",
        "line_sha256": "a8ca6a224fd089633161b7744087c1069072a0b7e21aeda2944a004b59c66c7c",
        "maximum": 1,
        "mode": "100644",
        "sha256": "720de71f0090c69b9536e614fde62b4e8d2d3bfc0364a50da2edaed15e065c04"
    },
    {
        "blob": "7c2d10f23f3ba63e89ae36823cc9e97d32250da1",
        "line_sha256": "9f97e89c1b0608c6ea3ecbaa75281130437cf0757f855c023e834acd9a042fc4",
        "maximum": 1,
        "mode": "100644",
        "sha256": "d3bdb695cbfec0ac35e909cfe1ff74a1c3ada5b2cf52654858943ea0864edcbb"
    },
    {
        "blob": "c2d4b7af95157b9673702ae3d14ce78f231e7f8e",
        "line_sha256": "dea9f61efc155a5b6bf870d7fcd3913de01ecce0c6a5deed8faa37aaf3be478d",
        "maximum": 1,
        "mode": "100644",
        "sha256": "35c0089351d5ba65ff3d466010e70ffaf44049f1ae4e9916a54fa0b3f4573dc6"
    },
    {
        "blob": "8be1dc127d7a2d052595f61d972f897e0783a5c4",
        "line_sha256": "53fbb93580c9ddb761dedfee4f8019fb13f339671b9e9f7eb74b51c2a8ade039",
        "maximum": 1,
        "mode": "100644",
        "sha256": "3b9a3a81722ccf7efcbae1c5ef5e7d768ad9f2558bd6bd9790833688bb8a4a44"
    },
    {
        "blob": "0c4dd9dbd9def05f3539df7f30ac426bf17901c6",
        "line_sha256": "9f97e89c1b0608c6ea3ecbaa75281130437cf0757f855c023e834acd9a042fc4",
        "maximum": 1,
        "mode": "100644",
        "sha256": "72727989f29ebbb1046fd6e777c252af29124eb02dce543108a760974f6318cc"
    },
    {
        "blob": "6896eb742d7e1a2f60297ee94e4885f54a63de68",
        "line_sha256": "e0ed194d8e0c5928a0464766bf00bf726ff2b125b74285bc59d074e9b16fb5f4",
        "maximum": 1,
        "mode": "100644",
        "sha256": "7da30283af794096248f3c997b6b5c14aa859ce6a5bf25015d88637ae2a146b6"
    },
    {
        "blob": "695e7a97b66612e7e6f8c4bb1d5c93986a925394",
        "line_sha256": "20e9081343af96f10be573b3b9629b7c6c9cba80c8805cf9c9016b309ec076c2",
        "maximum": 1,
        "mode": "100644",
        "sha256": "091f4a0e47d7f8c0fa927ee0f390806fe4de94a2c1020f83a8cec88ca76b6c30"
    },
    {
        "blob": "695e7a97b66612e7e6f8c4bb1d5c93986a925394",
        "line_sha256": "c15478d7ebd436b6d5420e6ebc39d10ef783fa65851793aa833ba2944ed088af",
        "maximum": 1,
        "mode": "100644",
        "sha256": "091f4a0e47d7f8c0fa927ee0f390806fe4de94a2c1020f83a8cec88ca76b6c30"
    },
    {
        "blob": "695e7a97b66612e7e6f8c4bb1d5c93986a925394",
        "line_sha256": "1aefdb1fccef0fb1c0aec8515d75d82c4436a3661b11bc988216058f444cef5f",
        "maximum": 1,
        "mode": "100644",
        "sha256": "091f4a0e47d7f8c0fa927ee0f390806fe4de94a2c1020f83a8cec88ca76b6c30"
    },
    {
        "blob": "695e7a97b66612e7e6f8c4bb1d5c93986a925394",
        "line_sha256": "a0e942c90a3c6f1935e4f1e9b39e0c3a13d01736ccf19080f6ddbb92eb02f011",
        "maximum": 1,
        "mode": "100644",
        "sha256": "091f4a0e47d7f8c0fa927ee0f390806fe4de94a2c1020f83a8cec88ca76b6c30"
    },
    {
        "blob": "695e7a97b66612e7e6f8c4bb1d5c93986a925394",
        "line_sha256": "5f111faab307e9dfbe34b7cfab5c9e7e010e93aefd41feae7d450cce1b886aa2",
        "maximum": 1,
        "mode": "100644",
        "sha256": "091f4a0e47d7f8c0fa927ee0f390806fe4de94a2c1020f83a8cec88ca76b6c30"
    },
    {
        "blob": "695e7a97b66612e7e6f8c4bb1d5c93986a925394",
        "line_sha256": "8e543c85888e398c2e7a99aae3e832ffdff824188f2c54f985129336209b8ac9",
        "maximum": 1,
        "mode": "100644",
        "sha256": "091f4a0e47d7f8c0fa927ee0f390806fe4de94a2c1020f83a8cec88ca76b6c30"
    },
    {
        "blob": "695e7a97b66612e7e6f8c4bb1d5c93986a925394",
        "line_sha256": "e132e006c127061559db0f0ff1eace5508981c3c829a91c20b19e54ef473eedd",
        "maximum": 1,
        "mode": "100644",
        "sha256": "091f4a0e47d7f8c0fa927ee0f390806fe4de94a2c1020f83a8cec88ca76b6c30"
    },
    {
        "blob": "695e7a97b66612e7e6f8c4bb1d5c93986a925394",
        "line_sha256": "14c8b000fb1c1fa5aa142ed451bffb950af7b915430d7656d6e11ca322fda649",
        "maximum": 1,
        "mode": "100644",
        "sha256": "091f4a0e47d7f8c0fa927ee0f390806fe4de94a2c1020f83a8cec88ca76b6c30"
    },
    {
        "blob": "695e7a97b66612e7e6f8c4bb1d5c93986a925394",
        "line_sha256": "7cb91e334a26a147198df12b2bf2dc59dcb7ca815ac570d4638503dab75d7801",
        "maximum": 1,
        "mode": "100644",
        "sha256": "091f4a0e47d7f8c0fa927ee0f390806fe4de94a2c1020f83a8cec88ca76b6c30"
    },
    {
        "blob": "695e7a97b66612e7e6f8c4bb1d5c93986a925394",
        "line_sha256": "abf756641cfb99063d7ee8317f97f0c0ac7f3515ed4a2b8331bde9e06ec60ab0",
        "maximum": 1,
        "mode": "100644",
        "sha256": "091f4a0e47d7f8c0fa927ee0f390806fe4de94a2c1020f83a8cec88ca76b6c30"
    },
    {
        "blob": "3e78e281e610d58af0cc4e703c57898c8051fa54",
        "line_sha256": "a880b75ee837109d0a167a73fdb623309570619f7f100c00cd0587509fa26408",
        "maximum": 1,
        "mode": "100644",
        "sha256": "43dc8fb4a77618f3ced34e569a05e71eeb01d0b0600dd1832819736060a396ca"
    },
    {
        "blob": "f01a0a1bd9b01dc7c9ba27eb2146d682358e763f",
        "line_sha256": "99986014c0b3376d58862f24d6ce32867e475533a4abcd4fef7e129277203ccb",
        "maximum": 1,
        "mode": "100644",
        "sha256": "50fa7b0ffc0ca64f93d72924872c2a1742e4dc2ad4ab0cc4051bfed41b4d85f5"
    },
    {
        "blob": "8be1dc127d7a2d052595f61d972f897e0783a5c4",
        "line_sha256": "53fbb93580c9ddb761dedfee4f8019fb13f339671b9e9f7eb74b51c2a8ade039",
        "maximum": 1,
        "mode": "100644",
        "sha256": "3b9a3a81722ccf7efcbae1c5ef5e7d768ad9f2558bd6bd9790833688bb8a4a44"
    },
    {
        "blob": "640c75dd6f592b21ed5ce11644ea0a5e23fe1c03",
        "line_sha256": None,
        "maximum": 1,
        "mode": "100644",
        "sha256": "9bf3d02e9290b60529c1c26050037f3143d08f627cd3a38777dbd6d9ad6f3198"
    },
    {
        "blob": "70fbb595ea5648cb85dc8e11ecc725838b4fe373",
        "line_sha256": "25bd5c6548d84a863cf353e981ae38509d44c9d891b704975ab8c8446a9f8093",
        "maximum": 1,
        "mode": "100644",
        "sha256": "2d2b71b0869259d8f5d108017cdf4b60e827eaf11d7c9102c092fe9208c784a6"
    },
    {
        "blob": "8bc6083d2f2febce67451c22a6de141c0f6aa932",
        "line_sha256": "4082264074525d35c5023a970163aa5e67941dc8b1db1d4dd471f5883696618a",
        "maximum": 1,
        "mode": "100644",
        "sha256": "28138d78096dc9045e15249b8cb82b6cc4b8df9e882d29828d0b13c00e269aef"
    }
]

REVIEWED_IDENTITIES = [
    [
        "history",
        "scripts/validate_middleware_v3_log_redaction.py",
        2,
        "jwt",
        42,
        42
    ],
    [
        "history",
        "scripts/validate_middleware_v3_log_redaction.py",
        2,
        "stripe-access-token",
        51,
        51
    ],
    [
        "history",
        "upstream/docs/sources/reference/components/loki/loki.secretfilter.md",
        1,
        "generic-api-key",
        244,
        244
    ],
    [
        "history",
        "upstream/docs/sources/reference/components/otelcol/otelcol.receiver.cloudflare.md",
        1,
        "generic-api-key",
        103,
        103
    ],
    [
        "history",
        "upstream/internal/component/common/net/config_test.go",
        1,
        "private-key",
        156,
        169
    ],
    [
        "history",
        "upstream/internal/component/common/net/config_test.go",
        1,
        "private-key",
        183,
        196
    ],
    [
        "history",
        "upstream/internal/component/loki/source/heroku/heroku_test.go",
        1,
        "heroku-api-key",
        50,
        50
    ],
    [
        "history",
        "upstream/internal/component/loki/source/heroku/heroku_test.go",
        1,
        "heroku-api-key",
        152,
        152
    ],
    [
        "history",
        "upstream/internal/component/loki/source/heroku/routes_test.go",
        1,
        "heroku-api-key",
        23,
        23
    ],
    [
        "history",
        "upstream/internal/component/loki/source/heroku/routes_test.go",
        1,
        "heroku-api-key",
        24,
        24
    ],
    [
        "history",
        "upstream/internal/component/loki/source/internal/kafkatarget/testdata/example.com-key.pem",
        1,
        "private-key",
        1,
        1
    ],
    [
        "history",
        "upstream/internal/component/loki/source/syslog/internal/syslogtarget/syslogtarget_test.go",
        1,
        "private-key",
        74,
        124
    ],
    [
        "history",
        "upstream/internal/component/loki/source/syslog/internal/syslogtarget/syslogtarget_test.go",
        1,
        "private-key",
        162,
        212
    ],
    [
        "history",
        "upstream/internal/component/loki/source/syslog/internal/syslogtarget/syslogtarget_test.go",
        1,
        "private-key",
        248,
        298
    ],
    [
        "history",
        "upstream/internal/component/otelcol/processor/redaction/redaction_test.go",
        1,
        "generic-api-key",
        149,
        149
    ],
    [
        "history",
        "upstream/internal/component/otelcol/processor/redaction/redaction_test.go",
        1,
        "generic-api-key",
        161,
        161
    ],
    [
        "history",
        "upstream/internal/component/otelcol/processor/redaction/redaction_test.go",
        1,
        "generic-api-key",
        198,
        198
    ],
    [
        "history",
        "upstream/internal/component/pyroscope/write/promhttp2/testdata/secrets.go",
        1,
        "private-key",
        12,
        63
    ],
    [
        "history",
        "upstream/internal/component/pyroscope/write/promhttp2/testdata/secrets.go",
        1,
        "private-key",
        65,
        116
    ],
    [
        "history",
        "upstream/internal/component/pyroscope/write/promhttp2/testdata/secrets.go",
        1,
        "private-key",
        118,
        169
    ],
    [
        "history",
        "upstream/internal/converter/internal/otelcolconvert/testdata/cloudflarereceiver.alloy",
        1,
        "generic-api-key",
        3,
        3
    ],
    [
        "history",
        "upstream/internal/converter/internal/otelcolconvert/testdata/cloudflarereceiver.yaml",
        1,
        "generic-api-key",
        8,
        8
    ],
    [
        "history",
        "upstream/internal/converter/internal/otelcolconvert/testdata/redactionprocessor.alloy",
        1,
        "generic-api-key",
        27,
        27
    ],
    [
        "history",
        "upstream/internal/converter/internal/otelcolconvert/testdata/redactionprocessor.yaml",
        1,
        "generic-api-key",
        28,
        28
    ],
    [
        "history",
        "upstream/internal/converter/internal/staticconvert/testdata-v2/integrations_v2.alloy",
        1,
        "generic-api-key",
        267,
        267
    ],
    [
        "history",
        "upstream/internal/converter/internal/staticconvert/testdata-v2/integrations_v2.yaml",
        1,
        "generic-api-key",
        136,
        136
    ],
    [
        "history",
        "upstream/internal/converter/internal/staticconvert/testdata/example-key.pem",
        1,
        "private-key",
        1,
        27
    ],
    [
        "history",
        "upstream/internal/converter/internal/staticconvert/testdata/integrations.alloy",
        1,
        "generic-api-key",
        330,
        330
    ],
    [
        "history",
        "upstream/internal/converter/internal/staticconvert/testdata/integrations.yaml",
        1,
        "generic-api-key",
        95,
        95
    ],
    [
        "history",
        "upstream/internal/pipelinetest/tests/loki-pipeline-file/api.log",
        1,
        "generic-api-key",
        1,
        1
    ],
    [
        "history",
        "upstream/internal/pipelinetest/tests/loki-pipeline-file/api.log",
        1,
        "generic-api-key",
        11,
        11
    ],
    [
        "history",
        "upstream/internal/pipelinetest/tests/loki-pipeline-file/api.log",
        1,
        "generic-api-key",
        21,
        21
    ],
    [
        "history",
        "upstream/internal/pipelinetest/tests/loki-pipeline-file/api.log",
        1,
        "generic-api-key",
        31,
        31
    ],
    [
        "history",
        "upstream/internal/pipelinetest/tests/loki-pipeline-file/api.log",
        1,
        "generic-api-key",
        41,
        41
    ],
    [
        "history",
        "upstream/internal/pipelinetest/tests/loki-pipeline-file/api.log",
        1,
        "generic-api-key",
        51,
        51
    ],
    [
        "history",
        "upstream/internal/pipelinetest/tests/loki-pipeline-file/api.log",
        1,
        "generic-api-key",
        61,
        61
    ],
    [
        "history",
        "upstream/internal/pipelinetest/tests/loki-pipeline-file/api.log",
        1,
        "generic-api-key",
        71,
        71
    ],
    [
        "history",
        "upstream/internal/pipelinetest/tests/loki-pipeline-file/api.log",
        1,
        "generic-api-key",
        81,
        81
    ],
    [
        "history",
        "upstream/internal/pipelinetest/tests/loki-pipeline-file/api.log",
        1,
        "generic-api-key",
        91,
        91
    ],
    [
        "history",
        "upstream/internal/pipelinetest/tests/loki-pipeline/test.yaml",
        1,
        "generic-api-key",
        26,
        26
    ],
    [
        "history",
        "upstream/internal/service/http/testdata/test-key.key",
        1,
        "private-key",
        1,
        52
    ],
    [
        "history",
        "upstream/internal/static/server/testdata/example-key.pem",
        1,
        "private-key",
        1,
        27
    ],
    [
        "history",
        "upstream/internal/static/server/testdata/windows/client_key.key",
        1,
        "private-key",
        7,
        36
    ],
    [
        "history",
        "upstream/internal/static/server/testdata/windows/client_key_unencrypted.key",
        1,
        "private-key",
        1,
        27
    ],
    [
        "tree",
        "upstream/docs/sources/reference/components/loki/loki.secretfilter.md",
        0,
        "generic-api-key",
        244,
        244
    ],
    [
        "tree",
        "upstream/docs/sources/reference/components/otelcol/otelcol.receiver.cloudflare.md",
        0,
        "generic-api-key",
        103,
        103
    ],
    [
        "tree",
        "upstream/internal/component/common/net/config_test.go",
        0,
        "private-key",
        156,
        169
    ],
    [
        "tree",
        "upstream/internal/component/common/net/config_test.go",
        0,
        "private-key",
        183,
        196
    ],
    [
        "tree",
        "upstream/internal/component/loki/source/heroku/heroku_test.go",
        0,
        "heroku-api-key",
        50,
        50
    ],
    [
        "tree",
        "upstream/internal/component/loki/source/heroku/heroku_test.go",
        0,
        "heroku-api-key",
        152,
        152
    ],
    [
        "tree",
        "upstream/internal/component/loki/source/heroku/routes_test.go",
        0,
        "heroku-api-key",
        23,
        23
    ],
    [
        "tree",
        "upstream/internal/component/loki/source/heroku/routes_test.go",
        0,
        "heroku-api-key",
        24,
        24
    ],
    [
        "tree",
        "upstream/internal/component/loki/source/internal/kafkatarget/testdata/example.com-key.pem",
        0,
        "private-key",
        1,
        1
    ],
    [
        "tree",
        "upstream/internal/component/loki/source/syslog/internal/syslogtarget/syslogtarget_test.go",
        0,
        "private-key",
        74,
        124
    ],
    [
        "tree",
        "upstream/internal/component/loki/source/syslog/internal/syslogtarget/syslogtarget_test.go",
        0,
        "private-key",
        162,
        212
    ],
    [
        "tree",
        "upstream/internal/component/loki/source/syslog/internal/syslogtarget/syslogtarget_test.go",
        0,
        "private-key",
        248,
        298
    ],
    [
        "tree",
        "upstream/internal/component/otelcol/processor/redaction/redaction_test.go",
        0,
        "generic-api-key",
        149,
        149
    ],
    [
        "tree",
        "upstream/internal/component/otelcol/processor/redaction/redaction_test.go",
        0,
        "generic-api-key",
        161,
        161
    ],
    [
        "tree",
        "upstream/internal/component/otelcol/processor/redaction/redaction_test.go",
        0,
        "generic-api-key",
        198,
        198
    ],
    [
        "tree",
        "upstream/internal/component/pyroscope/write/promhttp2/testdata/secrets.go",
        0,
        "private-key",
        12,
        63
    ],
    [
        "tree",
        "upstream/internal/component/pyroscope/write/promhttp2/testdata/secrets.go",
        0,
        "private-key",
        65,
        116
    ],
    [
        "tree",
        "upstream/internal/component/pyroscope/write/promhttp2/testdata/secrets.go",
        0,
        "private-key",
        118,
        169
    ],
    [
        "tree",
        "upstream/internal/converter/internal/otelcolconvert/testdata/cloudflarereceiver.alloy",
        0,
        "generic-api-key",
        3,
        3
    ],
    [
        "tree",
        "upstream/internal/converter/internal/otelcolconvert/testdata/cloudflarereceiver.yaml",
        0,
        "generic-api-key",
        8,
        8
    ],
    [
        "tree",
        "upstream/internal/converter/internal/otelcolconvert/testdata/redactionprocessor.alloy",
        0,
        "generic-api-key",
        27,
        27
    ],
    [
        "tree",
        "upstream/internal/converter/internal/otelcolconvert/testdata/redactionprocessor.yaml",
        0,
        "generic-api-key",
        28,
        28
    ],
    [
        "tree",
        "upstream/internal/converter/internal/staticconvert/testdata-v2/integrations_v2.alloy",
        0,
        "generic-api-key",
        267,
        267
    ],
    [
        "tree",
        "upstream/internal/converter/internal/staticconvert/testdata-v2/integrations_v2.yaml",
        0,
        "generic-api-key",
        136,
        136
    ],
    [
        "tree",
        "upstream/internal/converter/internal/staticconvert/testdata/example-key.pem",
        0,
        "private-key",
        1,
        27
    ],
    [
        "tree",
        "upstream/internal/converter/internal/staticconvert/testdata/integrations.alloy",
        0,
        "generic-api-key",
        330,
        330
    ],
    [
        "tree",
        "upstream/internal/converter/internal/staticconvert/testdata/integrations.yaml",
        0,
        "generic-api-key",
        95,
        95
    ],
    [
        "tree",
        "upstream/internal/pipelinetest/tests/loki-pipeline-file/api.log",
        0,
        "generic-api-key",
        1,
        1
    ],
    [
        "tree",
        "upstream/internal/pipelinetest/tests/loki-pipeline-file/api.log",
        0,
        "generic-api-key",
        11,
        11
    ],
    [
        "tree",
        "upstream/internal/pipelinetest/tests/loki-pipeline-file/api.log",
        0,
        "generic-api-key",
        21,
        21
    ],
    [
        "tree",
        "upstream/internal/pipelinetest/tests/loki-pipeline-file/api.log",
        0,
        "generic-api-key",
        31,
        31
    ],
    [
        "tree",
        "upstream/internal/pipelinetest/tests/loki-pipeline-file/api.log",
        0,
        "generic-api-key",
        41,
        41
    ],
    [
        "tree",
        "upstream/internal/pipelinetest/tests/loki-pipeline-file/api.log",
        0,
        "generic-api-key",
        51,
        51
    ],
    [
        "tree",
        "upstream/internal/pipelinetest/tests/loki-pipeline-file/api.log",
        0,
        "generic-api-key",
        61,
        61
    ],
    [
        "tree",
        "upstream/internal/pipelinetest/tests/loki-pipeline-file/api.log",
        0,
        "generic-api-key",
        71,
        71
    ],
    [
        "tree",
        "upstream/internal/pipelinetest/tests/loki-pipeline-file/api.log",
        0,
        "generic-api-key",
        81,
        81
    ],
    [
        "tree",
        "upstream/internal/pipelinetest/tests/loki-pipeline-file/api.log",
        0,
        "generic-api-key",
        91,
        91
    ],
    [
        "tree",
        "upstream/internal/pipelinetest/tests/loki-pipeline/test.yaml",
        0,
        "generic-api-key",
        26,
        26
    ],
    [
        "tree",
        "upstream/internal/service/http/testdata/test-key.key",
        0,
        "private-key",
        1,
        52
    ],
    [
        "tree",
        "upstream/internal/static/server/testdata/example-key.pem",
        0,
        "private-key",
        1,
        27
    ],
    [
        "tree",
        "upstream/internal/static/server/testdata/windows/client_cert.pfx",
        0,
        "pkcs12-file",
        0,
        0
    ],
    [
        "tree",
        "upstream/internal/static/server/testdata/windows/client_key.key",
        0,
        "private-key",
        7,
        36
    ],
    [
        "tree",
        "upstream/internal/static/server/testdata/windows/client_key_unencrypted.key",
        0,
        "private-key",
        1,
        27
    ]
]

VERIFIED = {}
for identity, proof in zip(REVIEWED_IDENTITIES, REVIEWED_PROOFS, strict=True):
    scope, path, commit_index, rule, start, end = identity
    commit = REVIEWED_COMMITS[commit_index]
    fingerprint = (commit + ":" if scope == "history" else "") + path + ":" + rule + ":" + str(start)
    VERIFIED[(scope, path, commit, rule, start, end, fingerprint)] = proof


def git_identity(kind, commit, path, root=Path('.')):
    if kind == 'history':
        raw = subprocess.check_output(['git', 'ls-tree', '-z', commit, '--', path], cwd=root, timeout=30)
        entries = [entry for entry in raw.decode().split('\0') if entry]
        if len(entries) != 1:
            raise ValueError('Missing historical Git object')
        metadata, observed = entries[0].split('\t', 1)
        mode, object_type, blob = metadata.split()
        if observed != path or object_type != 'blob':
            raise ValueError('Unexpected historical object')
        content = subprocess.check_output(['git', 'cat-file', 'blob', blob], cwd=root, timeout=30)
    else:
        raw = subprocess.check_output(['git', 'ls-files', '--stage', '-z', '--', path], cwd=root, timeout=30)
        entries = [entry for entry in raw.decode().split('\0') if entry]
        if len(entries) != 1:
            raise ValueError('Missing current Git object')
        metadata, observed = entries[0].split('\t', 1)
        mode, indexed_blob, stage = metadata.split()
        file = root / path
        if observed != path or stage != '0' or file.is_symlink():
            raise ValueError('Unexpected current object')
        content = file.read_bytes()
        blob = hashlib.sha1(f'blob {len(content)}\0'.encode() + content).hexdigest()
        if blob != indexed_blob:
            raise ValueError('Current working tree differs from Git index')
    return {'mode': mode, 'blob': blob, 'sha256': hashlib.sha256(content).hexdigest(), 'content': content}


def verify_findings(findings, kind, status, lookup=git_identity):
    if kind not in ('history', 'tree') or type(status) is not int or status not in (0, 1):
        return ['Scanner execution failed or unknown scan scope']
    if not isinstance(findings, list) or (status == 1) != bool(findings):
        return ['Scanner status/report mismatch']
    errors, counts = [], Counter()
    for finding in findings:
        if not isinstance(finding, dict):
            errors.append('Malformed scanner finding'); continue
        path, commit, rule = (finding.get(k) for k in ('File', 'Commit', 'RuleID'))
        start, end, fingerprint = (finding.get(k) for k in ('StartLine', 'EndLine', 'Fingerprint'))
        if not all(type(v) is str for v in (path, commit, rule, fingerprint)) or any(type(v) is not int for v in (start, end)):
            errors.append('Malformed scanner identity'); continue
        key = (kind, path, commit, rule, start, end, fingerprint)
        spec = VERIFIED.get(key)
        if spec is None:
            errors.append('Unapproved finding: ' + fingerprint); continue
        counts[key] += 1
        if counts[key] > spec['maximum']:
            errors.append('Unexpected duplicate finding: ' + fingerprint); continue
        try:
            actual = lookup(kind, commit, path)
            if any(actual.get(k) != spec[k] for k in ('mode', 'blob', 'sha256')):
                raise ValueError('Fixture file identity differs')
            content = actual['content']
            if type(content) is not bytes:
                raise ValueError('Fixture bytes missing')
            if hashlib.sha256(content).hexdigest() != spec['sha256']:
                raise ValueError('Fixture content differs')
            if start == 0:
                if kind != 'tree' or rule != 'pkcs12-file' or end != 0 or spec['line_sha256'] is not None:
                    raise ValueError('Unexpected binary fixture scope')
            else:
                if start < 1 or end < start or end > len(content.splitlines()):
                    raise ValueError('Invalid fixture range')
                linehash = hashlib.sha256(b'\n'.join(content.splitlines()[start-1:end])).hexdigest()
                if linehash != spec['line_sha256']:
                    raise ValueError('Fixture line range differs')
        except (OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError):
            errors.append('Fixture exact Git identity proof failed: ' + fingerprint)
    return errors


def scanner_regression(scanner):
    """Real scanner proof: an approved fixture cannot mask an adjacent new key."""
    original = Path.cwd()
    path = 'upstream/internal/static/server/testdata/example-key.pem'
    public_fixture = (original / path).read_bytes()
    with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as reports:
        root = Path(directory); fixture = root / path
        fixture.parent.mkdir(parents=True); fixture.write_bytes(public_fixture)
        subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
        subprocess.run(['git', 'add', '.'], cwd=root, check=True)
        def scan():
            report = Path(reports) / 'findings.json'
            result = subprocess.run([str(Path(scanner).resolve()), 'dir', '--no-banner', '--redact=100',
                                     '--exit-code', '1', '--report-format', 'json', '--report-path', str(report), '.'],
                                    cwd=root, capture_output=True)
            return verify_findings(json.loads(report.read_text()), 'tree', result.returncode,
                                   lambda kind, commit, name: git_identity(kind, commit, name, root))
        if scan(): raise ValueError('Exact public fixture control failed')
        adjacent = fixture.parent / 'new-active-credential.key'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:1024',
                        '-out', str(adjacent)], check=True, capture_output=True)
        subprocess.run(['git', 'add', '.'], cwd=root, check=True)
        if not scan(): raise ValueError('Adjacent unapproved credential escaped scanning')
    print('REAL_SCANNER_ADJACENT_CREDENTIAL_REJECTED=PASS')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--history-report', required=True)
    parser.add_argument('--tree-report', required=True)
    parser.add_argument('--history-status', type=int, required=True)
    parser.add_argument('--tree-status', type=int, required=True)
    parser.add_argument('--self-test-scanner', required=True)
    args = parser.parse_args()
    errors = []
    for kind in ('history', 'tree'):
        try:
            findings = json.loads(Path(getattr(args, kind + '_report')).read_text())
            failures = verify_findings(findings, kind, getattr(args, kind + '_status'))
            errors.extend(failures)
            print(f'{kind.upper()}_UNAPPROVED_FINDINGS={len(failures)}')
        except (OSError, ValueError): errors.append(kind + ' scanner report missing or malformed')
    if errors: raise SystemExit('\n'.join(errors))
    scanner_regression(args.self_test_scanner)
    print('Only exact immutable public synthetic fixtures classified; every other finding remains fatal')


if __name__ == '__main__': main()
