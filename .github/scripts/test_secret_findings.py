import copy
from pathlib import Path
import tempfile
import unittest

from verify_secret_findings import VERIFIED, git_identity, verify_findings


def finding(key):
    return dict(zip(('File', 'Commit', 'RuleID', 'StartLine', 'EndLine', 'Fingerprint'), key[1:]))


class SecretFindingTests(unittest.TestCase):
    def setUp(self):
        self.key = next(k for k in VERIFIED if k[0] == 'tree' and k[3] == 'private-key')
        self.item = finding(self.key)

    def test_every_reviewed_history_and_tree_identity_matches_real_git_bytes(self):
        for kind in ('history', 'tree'):
            items = [finding(key) for key, spec in VERIFIED.items() if key[0] == kind for _ in range(spec['maximum'])]
            self.assertEqual([], verify_findings(items, kind, 1))

    def test_unknown_path_rule_commit_line_range_and_fingerprint_fail(self):
        for field, value in (('File', 'docs/new.key'), ('RuleID', 'jwt'), ('Commit', 'f' * 40), ('StartLine', 2), ('EndLine', 999), ('Fingerprint', 'forged')):
            item = dict(self.item, **{field: value})
            with self.subTest(field=field):
                self.assertTrue(verify_findings([item], 'tree', 1))

    def test_changed_file_blob_mode_hash_or_bytes_fails(self):
        actual = git_identity('tree', '', self.key[1])
        for field, value in (('mode', '100755'), ('blob', 'a' * 40), ('sha256', 'b' * 64), ('content', actual['content'] + b'changed')):
            changed = dict(actual, **{field: value})
            with self.subTest(field=field):
                self.assertTrue(verify_findings([self.item], 'tree', 1, lambda *_: changed))

    def test_adjacent_unapproved_findings_cannot_hide_behind_known_fixture(self):
        other = dict(self.item, File=self.item['File'] + '.new')
        self.assertTrue(verify_findings([self.item, other], 'tree', 1))

    def test_only_exact_reviewed_duplicate_count_is_allowed(self):
        key = next(k for k, spec in VERIFIED.items() if spec['maximum'] == 2)
        item = finding(key)
        self.assertEqual([], verify_findings([item, copy.deepcopy(item)], 'history', 1))
        self.assertTrue(verify_findings([item, item, item], 'history', 1))
        self.assertTrue(verify_findings([self.item, self.item], 'tree', 1))

    def test_historical_redaction_corpus_never_allows_current_tree_copy(self):
        key = next(k for k in VERIFIED if k[1] == 'scripts/validate_middleware_v3_log_redaction.py')
        item = finding(key)
        item['Commit'] = ''
        item['Fingerprint'] = ':'.join(item['Fingerprint'].split(':')[1:])
        self.assertTrue(verify_findings([item], 'tree', 1))

    def test_binary_pkcs12_fixture_is_tree_only_exact_zero_line_scope(self):
        key = next(k for k in VERIFIED if k[3] == 'pkcs12-file')
        item = finding(key)
        self.assertEqual([], verify_findings([item], 'tree', 1))
        self.assertTrue(verify_findings([item], 'history', 1))
        self.assertTrue(verify_findings([dict(item, EndLine=1)], 'tree', 1))

    def test_malformed_identity_types_are_fatal(self):
        for field, value in (('File', None), ('Commit', 0), ('RuleID', []), ('StartLine', True), ('EndLine', False), ('Fingerprint', {})):
            self.assertTrue(verify_findings([dict(self.item, **{field: value})], 'tree', 1))
        for value in (None, 'finding', []):
            self.assertTrue(verify_findings([value], 'tree', 1))

    def test_scanner_errors_missing_reports_and_status_mismatches_fail(self):
        for status in (True, False, 2, 127, -1, '1', None):
            self.assertTrue(verify_findings([], 'tree', status))
        for report, status in (([], 1), ([self.item], 0), ({}, 0), (None, 0)):
            self.assertTrue(verify_findings(report, 'tree', status))
        self.assertTrue(verify_findings([], 'other', 0))
        self.assertEqual([], verify_findings([], 'tree', 0))

    def test_lookup_errors_are_fatal(self):
        def fail(*_):
            raise ValueError('unavailable Git object')
        self.assertTrue(verify_findings([self.item], 'tree', 1, fail))

    def test_classifier_source_exception_is_only_exact_alloy_baseline(self):
        from validate_source_scope import validate
        path = '.github/scripts/verify_secret_findings.py'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / path).parent.mkdir(parents=True)
            (root / path).write_text('pass\n')
            manifest = {'repository': 'appolon1908/Codestra-Alloy',
                        'reviewed_base_sha': 'f0d6705a3e374608241bd3554400fa92a4ce9eb4'}
            self.assertEqual([], validate(root, {path: '100644'}, manifest))
            for field, value in (('repository', 'appolon1908/other'), ('reviewed_base_sha', 'a' * 40)):
                changed = dict(manifest, **{field: value})
                self.assertTrue(validate(root, {path: '100644'}, changed))


if __name__ == '__main__':
    unittest.main()
