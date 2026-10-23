"""Public format/integrity regression cases; no private repository data."""
from pathlib import Path
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest.mock import Mock, patch
import run_osv_scan as boundary


class PnpmDocumentBoundaryTests(unittest.TestCase):
    def check(self, content: str, accepted: bool, nested: str = '', reason: str = '(multi-document|document stream|document end)') -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lock = root / nested / 'pnpm-lock.yaml'
            lock.parent.mkdir(parents=True, exist_ok=True)
            lock.write_text(content, encoding='utf-8')
            if accepted:
                boundary._require_single_document_pnpm_lockfiles(root)
            else:
                with self.assertRaisesRegex(boundary.ScanBoundaryError, reason):
                    boundary._require_single_document_pnpm_lockfiles(root)

    def test_single_document(self):
        self.check("lockfileVersion: '9.0'\npackages: {}\n", True)

    def test_leading_marker_and_comments(self):
        self.check("# header\n--- # one\nlockfileVersion: '9.0'\npackages: {}\n", True)

    def test_directive_leading_marker_trailing_end(self):
        self.check("%YAML 1.2\n---\nlockfileVersion: '9.0'\npackages: {}\n...\n# tail\n", True)

    def test_bom_crlf_single(self):
        self.check("\ufeff---\r\nlockfileVersion: '9.0'\r\npackages: {}\r\n", True)

    def test_comment_or_indented_scalar_marker_not_stream(self):
        self.check("lockfileVersion: '9.0'\n# ---\nmetadata: |\n  ---\npackages: {}\n", True)

    def test_pnpm12_two_documents(self):
        self.check("---\npackages: {}\n---\npackages: {vitest: {}}\n", False)

    def test_first_document_has_no_marker(self):
        self.check("packages: {}\n---\npackages: {vitest: {}}\n", False)

    def test_midstream_bom_is_conservatively_refused(self):
        self.check("\ufeff---\r\npackages: {}\r\n\ufeff--- # application\r\npackages: {}\r\n", False, reason='mid-stream BOM')

    def test_empty_first_or_second_document_is_unsupported(self):
        self.check("---\n---\npackages: {}\n", False)
        self.check("packages: {}\n---\n", False)

    def test_content_after_end(self):
        self.check("packages: {}\n...\npackages: {vitest: {}}\n", False)

    def test_invalid_document_marker_inside_quoted_scalar(self):
        self.check('packages: {}\nmetadata: "line\n---\nline"\n', False)

    def test_nested_and_gitignored_locks_not_excluded(self):
        self.check("packages: {}\n---\npackages: {}\n", False, 'ignored/nested')
        self.check("packages: {}\n---\npackages: {}\n", False, 'node_modules/embedded')

    def test_unreadable_lock_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'pnpm-lock.yaml').write_text('packages: {}')
            with patch.object(boundary.os, 'open', side_effect=PermissionError('fixture')):
                with self.assertRaisesRegex(boundary.ScanBoundaryError, 'unreadable'):
                    boundary._require_single_document_pnpm_lockfiles(root)

    def test_symlink_lock_not_silently_read(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);outside=root/'data';outside.write_text('packages: {}');(root/'pnpm-lock.yaml').symlink_to(outside)
            with self.assertRaisesRegex(boundary.ScanBoundaryError, 'symlink'):
                boundary._require_single_document_pnpm_lockfiles(root)

    def test_cli_status_two_before_scanner_and_no_report(self):
        with tempfile.TemporaryDirectory() as temp:
            parent=Path(temp);root=parent/'repo';root.mkdir();(root/'pnpm-lock.yaml').write_text('packages: {}\n---\npackages: {}\n')
            binary=parent/'scanner';binary.write_text('#!/bin/sh\nexit 99\n');binary.chmod(0o700)
            config=parent/'config.toml';config.write_text('');report=parent/'report.json'
            def scanner_returns_clean_first_document(command, **kwargs):
                if '--output' in command:
                    report.write_text('{"results": []}')
                return boundary.subprocess.CompletedProcess(command, 0)
            scanner = Mock(side_effect=scanner_returns_clean_first_document)
            original_boundary = boundary.run_osv_scan
            def with_injected_scanner(**arguments):
                return original_boundary(**arguments, runner=scanner)
            errors = io.StringIO()
            with patch.object(boundary, 'run_osv_scan', side_effect=with_injected_scanner), contextlib.redirect_stderr(errors):
                status=boundary.main(['--binary',str(binary),'--config',str(config),'--report',str(report),'--repository-root',str(root)])
            self.assertEqual(status,2);self.assertIn('multi-document',errors.getvalue());scanner.assert_not_called();self.assertFalse(report.exists())

    def test_tag_anchor_and_inline_document_starts(self):
        for marker in ['--- !!map', '--- &application', '--- {packages: {}}', '--- |']:
            self.check('packages: {}\n'+marker+'\npackages: {}\n', False)

    def test_leading_inline_single_document_is_supported(self):
        self.check('--- {lockfileVersion: "9.0", packages: {}}\n', True)

    def test_document_end_cannot_hide_trailing_content(self):
        self.check('packages: {}\n... invalid\npackages: {}\n', False)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'POSIX FIFO fixture')
    def test_fifo_is_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);os.mkfifo(root/'pnpm-lock.yaml')
            with self.assertRaisesRegex(boundary.ScanBoundaryError, 'regular file'):
                boundary._require_single_document_pnpm_lockfiles(root)

    def test_single_document_cli_reaches_same_injected_scanner(self):
        with tempfile.TemporaryDirectory() as temp:
            parent=Path(temp);root=parent/'repo';root.mkdir();(root/'pnpm-lock.yaml').write_text('packages: {}\n')
            binary=parent/'scanner';binary.write_text('#!/bin/sh\nexit 99\n');binary.chmod(0o700)
            config=parent/'config.toml';config.write_text('');report=parent/'report.json'
            def clean_scanner(command, **kwargs):
                if '--output' in command:
                    report.write_text('{"results": []}')
                return boundary.subprocess.CompletedProcess(command, 0)
            scanner=Mock(side_effect=clean_scanner);original=boundary.run_osv_scan
            with patch.object(boundary,'run_osv_scan',side_effect=lambda **kw:original(**kw,runner=scanner)), contextlib.redirect_stdout(io.StringIO()):
                status=boundary.main(['--binary',str(binary),'--config',str(config),'--report',str(report),'--repository-root',str(root)])
            self.assertEqual(status,0);self.assertEqual(scanner.call_count,2);self.assertTrue(report.exists())

    def test_non_yaml_whitespace_cannot_hide_first_document(self):
        for prefix in ['\u00a0#: x\n', '\u3000#: x\n', '\u202f#: x\n']:
            self.check(prefix+'---\npackages: {}\n',False)

    def test_unicode_whitespace_is_not_a_document_end_comment(self):
        self.check('packages: {}\n... \u00a0# not a comment\n',False)

    def test_symlink_directory_is_not_traversed_or_read(self):
        with tempfile.TemporaryDirectory() as temp:
            parent=Path(temp);root=parent/'repo';outside=parent/'outside';root.mkdir();outside.mkdir()
            (outside/'pnpm-lock.yaml').write_text('packages: {}\n---\npackages: {}\n')
            (root/'vendor').symlink_to(outside,target_is_directory=True)
            with patch.object(boundary.os,'open',side_effect=AssertionError('outside read')) as opened:
                boundary._require_single_document_pnpm_lockfiles(root)
            opened.assert_not_called()

    def test_public_fixture_both_document_orders_rejected(self):
        fixtures=json.loads((Path(__file__).with_name('pnpm12_public_fixtures.json')).read_text(encoding='utf-8'))
        for name in ['public-multi','public-vulnerable-first']:
            self.check(fixtures[name],False)
        for name in ['public-app-single','public-manager-single']:
            self.check(fixtures[name],True)


if __name__ == '__main__':
    unittest.main()
