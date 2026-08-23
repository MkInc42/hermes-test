#!/usr/bin/env python3
"""Set up a pinned Tailwind CSS v4 build pipeline in a Django project.

This helper deliberately manages only Tailwind build plumbing. It does not copy
licensed UI components or make changes to production services.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

TAILWIND_VERSION = "4.3.3"
TAILWIND_PACKAGES = ("tailwindcss", "@tailwindcss/cli")
INPUT_CSS_PATH = Path("static/src/input.css")
OUTPUT_CSS_PATH = Path("static/css/app.css")
GITIGNORE_ENTRIES = ("node_modules/", "static/css/app.css")
DEFAULT_INPUT_CSS = '@import "tailwindcss";\n'
BRAND_TOKEN_INPUT_CSS = '''@import "tailwindcss";

/* Optional generic starter tokens. Replace these with your project's own brand values. */
@theme {
  --color-brand-primary: #1f2937;
  --color-brand-accent: #0f766e;
  --color-brand-surface: #f8fafc;
  --color-brand-ink: #111827;
}
'''


class SetupError(RuntimeError):
    """Represent an expected setup failure with a user-facing message."""


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments for the setup helper.

    Args:
        arguments: Optional argument sequence, primarily useful for tests.

    Returns:
        Parsed command-line options.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Set up an idempotent Django Tailwind CSS v4 build pipeline. "
            "Both tailwindcss and @tailwindcss/cli are pinned to 4.3.3, "
            "matching the currently inspected Covered On package lock."
        ),
        epilog=(
            "The normal run installs the pinned npm packages and builds "
            "static/css/app.css. --dry-run reports changes without writing "
            "files or running npm."
        ),
    )
    parser.add_argument(
        "project_path",
        type=Path,
        help="Django project directory to update (must already exist).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show planned changes without modifying files or running npm.",
    )
    parser.add_argument(
        "--brand-tokens",
        action="store_true",
        help=(
            "Use a small generic @theme starter when static/src/input.css "
            "is missing; never overwrites an existing input.css."
        ),
    )
    return parser.parse_args(arguments)


def display_path(path: Path) -> str:
    """Return a concise path for user-facing messages.

    Args:
        path: Path to display.

    Returns:
        Absolute path text, so output remains useful from any working directory.
    """
    return str(path.expanduser().resolve())


def load_package_json(package_path: Path) -> dict[str, Any]:
    """Load and validate package.json as a JSON object.

    Args:
        package_path: Location of package.json.

    Returns:
        Parsed package metadata.

    Raises:
        SetupError: If the file is unreadable, invalid JSON, or not an object.
    """
    if not package_path.exists():
        return {}
    try:
        package_data = json.loads(package_path.read_text(encoding="utf-8"))
    except OSError as error:
        raise SetupError(f"Cannot read {package_path}: {error}") from error
    except json.JSONDecodeError as error:
        raise SetupError(f"Invalid JSON in {package_path}: {error}") from error
    if not isinstance(package_data, dict):
        raise SetupError(f"{package_path} must contain a JSON object")
    return package_data


def package_json_text(package_data: dict[str, Any]) -> str:
    """Serialize package metadata in a stable, review-friendly format.

    Args:
        package_data: Package metadata to serialize.

    Returns:
        Two-space-indented JSON ending with one newline.
    """
    return json.dumps(package_data, indent=2, ensure_ascii=False) + "\n"


def configure_package_json(package_data: dict[str, Any]) -> bool:
    """Ensure build scripts and exact Tailwind package pins are present.

    Existing package sections and unrelated fields are preserved. Build-only
    packages stay in the section where an existing project already declares
    them; a new project receives a devDependencies section.

    Args:
        package_data: Mutable package metadata.

    Returns:
        True when package metadata changed, otherwise False.
    """
    changed = False
    scripts = package_data.setdefault("scripts", {})
    if not isinstance(scripts, dict):
        raise SetupError("package.json field 'scripts' must be an object")
    expected_scripts = {
        "build:css": "./node_modules/.bin/tailwindcss -i static/src/input.css -o static/css/app.css",
        "watch:css": "./node_modules/.bin/tailwindcss -i static/src/input.css -o static/css/app.css --watch",
    }
    for script_name, command in expected_scripts.items():
        if scripts.get(script_name) != command:
            scripts[script_name] = command
            changed = True

    dependency_sections: dict[str, dict[str, str]] = {}
    for section_name in ("dependencies", "devDependencies", "optionalDependencies"):
        section = package_data.get(section_name)
        if section is not None and not isinstance(section, dict):
            raise SetupError(f"package.json field '{section_name}' must be an object")
        if isinstance(section, dict):
            dependency_sections[section_name] = section

    default_section = dependency_sections.get("devDependencies")
    if default_section is None:
        default_section = {}
        package_data["devDependencies"] = default_section
        dependency_sections["devDependencies"] = default_section
        changed = True

    for package_name in TAILWIND_PACKAGES:
        containing_sections = [
            section for section, values in dependency_sections.items() if package_name in values
        ]
        section_name = containing_sections[0] if containing_sections else "devDependencies"
        dependencies = dependency_sections[section_name]
        if dependencies.get(package_name) != TAILWIND_VERSION:
            dependencies[package_name] = TAILWIND_VERSION
            changed = True
        # A duplicated declaration is ambiguous for maintainers and npm, so
        # retain the first existing section and remove later duplicates only.
        for duplicate_section in containing_sections[1:]:
            if package_name in dependency_sections[duplicate_section]:
                del dependency_sections[duplicate_section][package_name]
                changed = True

    return changed


def ensure_input_css(project_path: Path, use_brand_tokens: bool, dry_run: bool) -> str:
    """Create the Tailwind input stylesheet only when it is missing.

    Args:
        project_path: Django project root.
        use_brand_tokens: Whether to use the generic token starter.
        dry_run: Whether to report without writing.

    Returns:
        A status message describing the action.
    """
    input_path = project_path / INPUT_CSS_PATH
    if input_path.exists():
        if not input_path.is_file():
            raise SetupError(f"Expected {input_path} to be a file")
        return f"keep existing {INPUT_CSS_PATH}"

    content = BRAND_TOKEN_INPUT_CSS if use_brand_tokens else DEFAULT_INPUT_CSS
    if not dry_run:
        try:
            input_path.parent.mkdir(parents=True, exist_ok=True)
            input_path.write_text(content, encoding="utf-8")
        except OSError as error:
            raise SetupError(f"Cannot create {input_path}: {error}") from error
    template_name = "brand-token starter" if use_brand_tokens else "minimal import"
    return f"create {INPUT_CSS_PATH} ({template_name})"


def ensure_gitignore(project_path: Path, dry_run: bool) -> list[str]:
    """Add required ignore entries without removing existing content.

    Args:
        project_path: Django project root.
        dry_run: Whether to report without writing.

    Returns:
        The entries newly added, or the entries that would be added.

    Raises:
        SetupError: If .gitignore cannot be read or written.
    """
    gitignore_path = project_path / ".gitignore"
    try:
        existing_text = gitignore_path.read_text(encoding="utf-8") if gitignore_path.exists() else ""
    except OSError as error:
        raise SetupError(f"Cannot read {gitignore_path}: {error}") from error

    existing_entries = {line.strip() for line in existing_text.splitlines()}
    missing_entries = [entry for entry in GITIGNORE_ENTRIES if entry not in existing_entries]
    if missing_entries and not dry_run:
        updated_text = existing_text
        if updated_text and not updated_text.endswith("\n"):
            updated_text += "\n"
        if updated_text and not updated_text.endswith("\n\n"):
            updated_text += "\n"
        updated_text += "# Tailwind CSS build artifacts\n"
        updated_text += "\n".join(missing_entries) + "\n"
        try:
            gitignore_path.write_text(updated_text, encoding="utf-8")
        except OSError as error:
            raise SetupError(f"Cannot update {gitignore_path}: {error}") from error
    return missing_entries


def run_command(command: Sequence[str], project_path: Path, description: str) -> subprocess.CompletedProcess[str]:
    """Run a project command and convert OS failures to setup errors.

    Args:
        command: Executable and arguments to run.
        project_path: Working directory for the command.
        description: Human-readable operation name.

    Returns:
        Completed subprocess result with captured text output.

    Raises:
        SetupError: If the executable cannot be started.
    """
    try:
        return subprocess.run(
            list(command),
            cwd=project_path,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        raise SetupError(f"Cannot {description}: {error}") from error


def print_command_output(result: subprocess.CompletedProcess[str]) -> None:
    """Print captured subprocess output without hiding diagnostics.

    Args:
        result: Completed subprocess result to display.
    """
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)


def install_tailwind(project_path: Path) -> None:
    """Install the exact Tailwind package versions with npm.

    Args:
        project_path: Django project root.

    Raises:
        SetupError: If npm fails or is unavailable.
    """
    print(f"Installing tailwindcss@{TAILWIND_VERSION} and @tailwindcss/cli@{TAILWIND_VERSION}...")
    result = run_command(
        (
            "npm",
            "install",
            "--save-dev",
            "--save-exact",
            f"tailwindcss@{TAILWIND_VERSION}",
            f"@tailwindcss/cli@{TAILWIND_VERSION}",
        ),
        project_path,
        "run npm install",
    )
    print_command_output(result)
    if result.returncode != 0:
        raise SetupError(f"npm install failed with exit code {result.returncode}")


def build_css(project_path: Path) -> None:
    """Build CSS and verify that the output is a non-empty file.

    Args:
        project_path: Django project root.

    Raises:
        SetupError: If npm run build:css fails or output is missing/empty.
    """
    print("Building CSS with npm run build:css...")
    result = run_command(("npm", "run", "build:css"), project_path, "run npm run build:css")
    print_command_output(result)
    if result.returncode != 0:
        raise SetupError(f"npm run build:css failed with exit code {result.returncode}")
    output_path = project_path / OUTPUT_CSS_PATH
    try:
        output_size = output_path.stat().st_size
    except OSError as error:
        raise SetupError(f"CSS build did not create {output_path}: {error}") from error
    if output_size == 0:
        raise SetupError(f"CSS build created empty output {output_path}")
    print(f"Verified {OUTPUT_CSS_PATH} ({output_size} bytes).")


def setup_project(project_path: Path, dry_run: bool, use_brand_tokens: bool) -> None:
    """Apply the Tailwind setup to one existing project directory.

    Args:
        project_path: Target project directory.
        dry_run: Whether to report planned changes only.
        use_brand_tokens: Whether to use the generic missing-input template.

    Raises:
        SetupError: If validation or any setup operation fails.
    """
    resolved_project_path = project_path.expanduser().resolve()
    if not resolved_project_path.is_dir():
        raise SetupError(
            f"Target is not a directory: {project_path}. "
            "Create the Django project first or pass an existing directory."
        )

    mode = "DRY RUN: " if dry_run else ""
    print(f"{mode}Setting up Tailwind CSS v4 in {resolved_project_path}")
    print(f"Recommended exact pins: tailwindcss@{TAILWIND_VERSION}, @tailwindcss/cli@{TAILWIND_VERSION}")

    package_path = resolved_project_path / "package.json"
    package_data = load_package_json(package_path)
    package_changed = configure_package_json(package_data)
    if package_changed:
        print(f"{mode}{'update' if package_path.exists() else 'create'} package.json")
        if not dry_run:
            try:
                package_path.write_text(package_json_text(package_data), encoding="utf-8")
            except OSError as error:
                raise SetupError(f"Cannot write {package_path}: {error}") from error
    else:
        print("keep package.json (already configured)")

    print(f"{mode}{ensure_input_css(resolved_project_path, use_brand_tokens, dry_run)}")
    missing_gitignore_entries = ensure_gitignore(resolved_project_path, dry_run)
    if missing_gitignore_entries:
        print(f"{mode}add to .gitignore: {', '.join(missing_gitignore_entries)}")
    else:
        print("keep .gitignore (required entries already present)")

    if dry_run:
        print("Dry run complete; no files changed and npm was not run.")
        return

    install_tailwind(resolved_project_path)
    build_css(resolved_project_path)
    print("Tailwind CSS v4 setup complete.")


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the command-line helper and return a process exit code.

    Args:
        arguments: Optional argument sequence, primarily useful for tests.

    Returns:
        Zero on success, two for expected setup failures.
    """
    parsed_arguments = parse_arguments(arguments)
    try:
        setup_project(
            parsed_arguments.project_path,
            parsed_arguments.dry_run,
            parsed_arguments.brand_tokens,
        )
    except SetupError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
