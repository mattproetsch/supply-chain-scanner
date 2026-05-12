from . import npm, python, rust, golang, dotnet, gh_actions, gitlab_ci, dockerfile

ECOSYSTEMS = {
    "npm": npm,
    "python": python,
    "rust": rust,
    "go": golang,
    "dotnet": dotnet,
    "gh_actions": gh_actions,
    "gitlab_ci": gitlab_ci,
    "dockerfile": dockerfile,
}

PARSERS = [npm, python, rust, golang, dotnet, gh_actions, gitlab_ci, dockerfile]
