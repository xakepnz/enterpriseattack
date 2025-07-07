## Contributing

Thanks for considering to contribute to the enterpriseattack project. Contributions of all forms are always welcome!

## Git Commit Guidelines

This project uses commit messages to automatically determine the type of change.
Messages should adhere to the conventions of [Conventional Commits (v1.0.0-beta.2)](https://www.conventionalcommits.org/en/v1.0.0-beta.2/).

### Commit msg Syntax

```sh
<type>[optional scope]: <description>

[optional body]

[optional footer]
```

#### Examples

```sh
feat(auth): add login functionality  # Correct type, subject, within 72 characters

fix(api): Correct data parsing bug   # Correct type, subject, within 72 characters

docs(readme): update installation guide  # Correct type, subject, within 72 characters
```

## Reporting feature requests / bugs

Please [raise an issue](https://gitlab.com/xakepnz/enterpriseattack/-/issues) for feature requests or bugs

## Setup Dev Environment

First [fork the repository](https://gitlab.com/xakepnz/enterpriseattack/-/forks/new) locally.

Once forked, `clone` the repository and setup your virtualenv:

```sh
cd enterpriseattack

# install the dependencies
make

# start working out of a feature branch
git checkout -b feat/idea
```

### Pre-commit hooks

We use pre-commit hooks to ensure that what's committed to the repository has already passed validation checks locally.

Review the `.pre-commit-config.yaml` to see what checks run.

## Running unit tests

To run unit tests, please run `make test`
