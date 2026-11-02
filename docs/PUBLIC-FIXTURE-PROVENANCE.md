# Public fixture provenance and secret scanning

This source-only gate freezes every original file, path, Git blob and mode. It does not certify Alloy, vendor security, release readiness or runtime deployment.

Both Gitleaks 8.30.1 complete-history and effective-tree scans run without exclusions or ignored rules. Scanner errors, malformed reports, status/report disagreement and every unrecognized finding fail. The trusted CI classifier binds each reviewed finding to scan scope, exact path, historical commit where applicable, rule, start/end lines, fingerprint, bounded count, Git mode, complete raw Git blob, complete-file SHA256 and line-range SHA256. A binary PFX fixture is tree-only at exact zero-line scope and binds its entire raw file. No credential values appear in this evidence.

## Official upstream source

The following complete files were independently compared byte-for-byte with official grafana/alloy commit `041d2911a30a53f2c9c0317333aedee108a56b0a`. Original repository baseline is `f0d6705a3e374608241bd3554400fa92a4ce9eb4`. These are public documentation examples or test fixtures, not operational credentials.

| Frozen repository path | Official Git blob |
| --- | --- |
| `upstream/docs/sources/reference/components/loki/loki.secretfilter.md` | `cebdb760441a814503c740423990a60b05d7751b` |
| `upstream/docs/sources/reference/components/otelcol/otelcol.receiver.cloudflare.md` | `fbf411b5b333582ae352964aebfd8f86ddaba33c` |
| `upstream/internal/component/common/net/config_test.go` | `18924109da327176ed5442b214af5af0f28b7eea` |
| `upstream/internal/component/loki/source/heroku/heroku_test.go` | `8a1bb8592c91763144af5164c1e1387c79f70bcf` |
| `upstream/internal/component/loki/source/heroku/routes_test.go` | `faf0799ab313c291bce97b2f15993aeb1d9f4937` |
| `upstream/internal/component/loki/source/internal/kafkatarget/testdata/example.com-key.pem` | `acc0a7fabdc6cca27ccb95e0c106b05c59ffb70c` |
| `upstream/internal/component/loki/source/syslog/internal/syslogtarget/syslogtarget_test.go` | `db63c88e5e64a61d778e4b067dd5b0ddecc13076` |
| `upstream/internal/component/otelcol/processor/redaction/redaction_test.go` | `456c5145e2674e2ba8e7e3e237ef63306cff79e2` |
| `upstream/internal/component/pyroscope/write/promhttp2/testdata/secrets.go` | `56820979b0b4462dd12963d611a4da3c9176fa6c` |
| `upstream/internal/converter/internal/otelcolconvert/testdata/cloudflarereceiver.alloy` | `c8ac9e293c45154e913c14c13f26bf4d3850f198` |
| `upstream/internal/converter/internal/otelcolconvert/testdata/cloudflarereceiver.yaml` | `94ccd91a76689103521a322991456f7d8bdc8a7c` |
| `upstream/internal/converter/internal/otelcolconvert/testdata/redactionprocessor.alloy` | `fdbb0ba5b04468eeb5d4317d0bb9aa99901e3b43` |
| `upstream/internal/converter/internal/otelcolconvert/testdata/redactionprocessor.yaml` | `20d68d6cc0e40d6deeeab069900b3e34399ffdd3` |
| `upstream/internal/converter/internal/staticconvert/testdata-v2/integrations_v2.alloy` | `7c2d10f23f3ba63e89ae36823cc9e97d32250da1` |
| `upstream/internal/converter/internal/staticconvert/testdata-v2/integrations_v2.yaml` | `c2d4b7af95157b9673702ae3d14ce78f231e7f8e` |
| `upstream/internal/converter/internal/staticconvert/testdata/example-key.pem` | `8be1dc127d7a2d052595f61d972f897e0783a5c4` |
| `upstream/internal/converter/internal/staticconvert/testdata/integrations.alloy` | `0c4dd9dbd9def05f3539df7f30ac426bf17901c6` |
| `upstream/internal/converter/internal/staticconvert/testdata/integrations.yaml` | `6896eb742d7e1a2f60297ee94e4885f54a63de68` |
| `upstream/internal/pipelinetest/tests/loki-pipeline-file/api.log` | `695e7a97b66612e7e6f8c4bb1d5c93986a925394` |
| `upstream/internal/pipelinetest/tests/loki-pipeline/test.yaml` | `3e78e281e610d58af0cc4e703c57898c8051fa54` |
| `upstream/internal/service/http/testdata/test-key.key` | `f01a0a1bd9b01dc7c9ba27eb2146d682358e763f` |
| `upstream/internal/static/server/testdata/example-key.pem` | `8be1dc127d7a2d052595f61d972f897e0783a5c4` |
| `upstream/internal/static/server/testdata/windows/client_key.key` | `70fbb595ea5648cb85dc8e11ecc725838b4fe373` |
| `upstream/internal/static/server/testdata/windows/client_key_unencrypted.key` | `8bc6083d2f2febce67451c22a6de141c0f6aa932` |
| `upstream/internal/static/server/testdata/windows/client_cert.pfx` | `640c75dd6f592b21ed5ce11644ea0a5e23fe1c03` |

## Fixture semantics independently checked

Eleven actual PEM keys were parsed and matched to their accompanying public certificates: three syslog fixtures, three generated promhttp2 test fixtures, and one each in Kafka, converter, HTTP, static-server and unencrypted Windows TLS tests. The remaining two mock PEM strings in config tests contain literal test-key assertions rather than encoded keys. The Windows PFX is the official localhost Windows TLS test fixture described by its accompanying README; it receives no historical or generic binary exemption.

Heroku matches are UUID request identifiers inside test log messages. Generic matches are fixed repeated alphabet/number configuration examples, a documentation HMAC example and synthetic log-redaction/pipeline fixtures. Only the exact reviewed complete bytes and lines are recognized; no path, value pattern or rule is generically allowed.

## Historical owned redaction corpus

Three historical findings come from `scripts/validate_middleware_v3_log_redaction.py` at commit `8b6f55998d8034aa768bbb6f7a1064952a639075`, Git blob `fcff83e1cdc00d699039b77dad70fa581764c78e`, SHA256 `f159023876a9eca8525f32df24e04e7157bcc650ea758ce29604e903aa0dafac`. Its AST and docstring identify a planted redaction test corpus. The JWT example's printable nineteen-byte signature is not a valid thirty-two-byte HS256 MAC; the Stripe-like sample is a deliberately planted corpus string. Exactly one JWT finding at line 42 and at most two Stripe findings at line 51 are recognized only in that historical commit. No current-tree copy is allowed.

## Negative verification

Unit tests reject changed content, Git blob, mode, path, rule, commit, line range, fingerprint, malformed identity types, unexpected duplicates and scanner errors. Every CI run additionally scans a real approved public fixture beside a newly generated private key in a disposable directory: the fixture must classify successfully and the adjacent new key must block. There are no ignore flags or secret-scan thresholds to reduce.
