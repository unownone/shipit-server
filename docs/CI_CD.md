# CI/CD Pipeline Documentation

## Overview

The ShipIt Server uses GitHub Actions for continuous integration and deployment. The pipeline includes comprehensive testing, code quality checks, security scanning, and quality gates to ensure code quality and maintainability.

## Pipeline Components

### 1. Test Job
- **Purpose**: Run all tests with coverage reporting
- **Triggers**: On PR to main/master branch and direct pushes
- **Services**: PostgreSQL 15 for test database
- **Outputs**: Coverage reports and test results

### 2. Build Job
- **Purpose**: Build application binaries
- **Dependencies**: Test job must pass
- **Outputs**: Compiled binaries for different platforms

### 3. Security Job
- **Purpose**: Security vulnerability scanning
- **Tools**: Trivy vulnerability scanner
- **Outputs**: Security scan results uploaded to GitHub Security tab

### 4. Quality Gates Job
- **Purpose**: Enforce quality standards
- **Checks**: Coverage threshold (50% minimum)
- **Outputs**: PR comments with quality gate results

## Quality Gates

### Coverage Threshold
- **Minimum Coverage**: 50%
- **Enforcement**: Pipeline fails if coverage is below threshold
- **Reporting**: Coverage results posted as PR comments

### Code Quality
- **Linting**: golangci-lint with comprehensive rules
- **Formatting**: gofmt and goimports
- **Security**: gosec security scanner

## Local Development

### Running Tests with Coverage

```bash
# Run tests with coverage (same as CI)
make test-coverage

# Run tests without coverage
make test

# Clean test artifacts
make test-clean
```

### Coverage Reports

The coverage framework generates multiple report formats:

1. **coverage.out** - Raw coverage data
2. **coverage.html** - HTML report (opens in browser)
3. **coverage.txt** - Text summary
4. **coverage.json** - JSON format for tools
5. **coverage.xml** - XML format for Codecov

### Quality Gate Checks

The coverage framework enforces quality gates:

- Coverage must be ≥ 50%
- All tests must pass
- Code must pass linting

## Configuration

### Coverage Framework

The project uses industry-standard coverage tools:

- **gocov**: Converts Go coverage to JSON format
- **gocov-xml**: Converts JSON coverage to XML for Codecov
- **Codecov**: Professional coverage reporting and quality gates

### Environment Variables

- `GO_VERSION`: Go version to use (default: 1.24.2)
- `COVERAGE_THRESHOLD`: Minimum coverage percentage (default: 50)

### Linting Configuration

The `.golangci.yml` file configures the linter with:

- Code formatting (gofmt, goimports)
- Static analysis (govet, staticcheck)
- Security checks (gosec)
- Code quality (gosimple, ineffassign)
- Style enforcement (revive, gocritic)

## Workflow Triggers

The pipeline runs on:

1. **Pull Requests** to main/master branch
2. **Direct pushes** to main/master branch

## Artifacts

The pipeline generates several artifacts:

- **Coverage Reports**: HTML and text coverage reports
- **Build Binaries**: Compiled application binaries
- **Security Reports**: Trivy vulnerability scan results

## Monitoring

### Badges

The README includes badges for:

- CI/CD Pipeline status
- Code coverage percentage

### PR Comments

For pull requests, the pipeline automatically comments with:

- Quality gate results
- Coverage percentage
- Pass/fail status

## Troubleshooting

### Common Issues

1. **Coverage Below Threshold**
   - Add more tests to increase coverage
   - Review untested code paths
   - Consider if some code paths are truly untestable

2. **Linting Failures**
   - Run `make lint` locally to see issues
   - Fix formatting with `make format`
   - Address security warnings from gosec

3. **Test Failures**
   - Ensure PostgreSQL is running for local tests
   - Check test environment variables
   - Review test logs for specific failures

### Local Debugging

```bash
# Run specific test file
go test -v ./test/specific_test.go

# Run with verbose output
go test -v -count=1 ./test/...

# Run with race detection
go test -race ./test/...

# Run with coverage for specific package
go test -coverprofile=coverage.out ./internal/specific/package
```

## Best Practices

1. **Write Tests First**: Aim for high coverage from the start
2. **Run Locally**: Always test locally before pushing
3. **Review Coverage**: Regularly review coverage reports
4. **Security First**: Address security warnings promptly
5. **Quality Gates**: Don't bypass quality gates - fix issues instead

## Future Enhancements

Potential improvements to the pipeline:

1. **Performance Testing**: Add performance benchmarks
2. **Integration Testing**: More comprehensive integration tests
3. **Dependency Scanning**: Regular dependency vulnerability checks
4. **Deployment**: Automated deployment to staging/production
5. **Monitoring**: Integration with monitoring and alerting 