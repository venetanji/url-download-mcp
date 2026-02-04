"""Tests for command-line interface functionality."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class TestCommandLineArguments:
    """Tests for command-line argument parsing."""

    def test_no_arguments_uses_default_dirs(self, monkeypatch):
        """Test that no arguments uses default allowed directories."""
        # Save original ALLOWED_BASE_DIRS
        from mcp_url_downloader import server
        original_dirs = server.ALLOWED_BASE_DIRS.copy()
        
        try:
            # Reset to defaults
            server.ALLOWED_BASE_DIRS = [
                Path.home() / "Downloads",
                Path.home() / "Documents",
                Path.home() / "Desktop",
                Path("/tmp"),
            ]
            
            # Mock sys.argv and mcp.run
            monkeypatch.setattr(sys, "argv", ["mcp-url-downloader"])
            mock_run = MagicMock()
            
            with patch.object(server.mcp, "run", mock_run):
                server.main()
            
            # Should use default directories
            assert Path.home() / "Downloads" in server.ALLOWED_BASE_DIRS
            assert Path.home() / "Documents" in server.ALLOWED_BASE_DIRS
            assert Path.home() / "Desktop" in server.ALLOWED_BASE_DIRS
            assert Path("/tmp") in server.ALLOWED_BASE_DIRS
            
            # Verify mcp.run was called
            mock_run.assert_called_once_with(transport="stdio")
        finally:
            # Restore original
            server.ALLOWED_BASE_DIRS = original_dirs

    def test_custom_directories_override_defaults(self, monkeypatch, tmp_path):
        """Test that custom directories override default allowed directories."""
        from mcp_url_downloader import server
        original_dirs = server.ALLOWED_BASE_DIRS.copy()
        
        try:
            # Create test directories
            test_dir1 = tmp_path / "dir1"
            test_dir2 = tmp_path / "dir2"
            test_dir1.mkdir()
            test_dir2.mkdir()
            
            # Mock sys.argv and mcp.run
            monkeypatch.setattr(sys, "argv", ["mcp-url-downloader", str(test_dir1), str(test_dir2)])
            mock_run = MagicMock()
            
            with patch.object(server.mcp, "run", mock_run):
                server.main()
            
            # Should only have custom directories
            assert len(server.ALLOWED_BASE_DIRS) == 2
            assert test_dir1.resolve() in server.ALLOWED_BASE_DIRS
            assert test_dir2.resolve() in server.ALLOWED_BASE_DIRS
            
            # Default directories should not be present
            assert Path.home() / "Downloads" not in server.ALLOWED_BASE_DIRS
            
            # Verify mcp.run was called
            mock_run.assert_called_once_with(transport="stdio")
        finally:
            # Restore original
            server.ALLOWED_BASE_DIRS = original_dirs

    def test_single_custom_directory(self, monkeypatch, tmp_path):
        """Test with a single custom directory."""
        from mcp_url_downloader import server
        original_dirs = server.ALLOWED_BASE_DIRS.copy()
        
        try:
            # Create test directory
            test_dir = tmp_path / "custom_dir"
            test_dir.mkdir()
            
            # Mock sys.argv and mcp.run
            monkeypatch.setattr(sys, "argv", ["mcp-url-downloader", str(test_dir)])
            mock_run = MagicMock()
            
            with patch.object(server.mcp, "run", mock_run):
                server.main()
            
            # Should have only one custom directory
            assert len(server.ALLOWED_BASE_DIRS) == 1
            assert test_dir.resolve() in server.ALLOWED_BASE_DIRS
            
            # Verify mcp.run was called
            mock_run.assert_called_once_with(transport="stdio")
        finally:
            # Restore original
            server.ALLOWED_BASE_DIRS = original_dirs

    def test_relative_paths_resolved_to_absolute(self, monkeypatch, tmp_path):
        """Test that relative paths are resolved to absolute paths."""
        from mcp_url_downloader import server
        original_dirs = server.ALLOWED_BASE_DIRS.copy()
        
        try:
            # Use a relative path
            monkeypatch.setattr(sys, "argv", ["mcp-url-downloader", "."])
            mock_run = MagicMock()
            
            with patch.object(server.mcp, "run", mock_run):
                server.main()
            
            # All paths should be absolute
            for path in server.ALLOWED_BASE_DIRS:
                assert path.is_absolute()
            
            # Verify mcp.run was called
            mock_run.assert_called_once_with(transport="stdio")
        finally:
            # Restore original
            server.ALLOWED_BASE_DIRS = original_dirs


class TestValidateOutputDirWithCustomDirs:
    """Tests for _validate_output_dir with custom allowed directories."""

    def test_custom_dir_is_allowed(self, tmp_path, monkeypatch):
        """Test that a custom allowed directory is accepted."""
        from mcp_url_downloader.server import ALLOWED_BASE_DIRS, _validate_output_dir
        from mcp_url_downloader import server
        
        original_dirs = server.ALLOWED_BASE_DIRS.copy()
        
        try:
            # Set custom allowed directory
            test_dir = tmp_path / "allowed"
            test_dir.mkdir()
            server.ALLOWED_BASE_DIRS = [test_dir.resolve()]
            
            # Test subdirectory within allowed directory
            subdir = test_dir / "subdir"
            result = _validate_output_dir(str(subdir))
            
            assert result.is_absolute()
            assert result == subdir.resolve()
        finally:
            # Restore original
            server.ALLOWED_BASE_DIRS = original_dirs

    def test_directory_outside_custom_dirs_blocked(self, tmp_path, monkeypatch):
        """Test that directories outside custom allowed dirs are blocked."""
        from mcp_url_downloader.server import _validate_output_dir
        from mcp_url_downloader import server
        
        original_dirs = server.ALLOWED_BASE_DIRS.copy()
        
        try:
            # Set custom allowed directory
            test_dir = tmp_path / "allowed"
            test_dir.mkdir()
            server.ALLOWED_BASE_DIRS = [test_dir.resolve()]
            
            # Try to use a directory outside the allowed directory
            forbidden_dir = tmp_path / "forbidden"
            forbidden_dir.mkdir()
            
            with pytest.raises(ValueError, match="allowed locations"):
                _validate_output_dir(str(forbidden_dir))
        finally:
            # Restore original
            server.ALLOWED_BASE_DIRS = original_dirs
