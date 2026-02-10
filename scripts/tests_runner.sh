#!/bin/bash

################################################################################
# tests_runner.sh - Comprehensive test runner for VulnRadar project
#
# This script provides various testing and linting options including:
# - Running all tests
# - Generating coverage reports
# - Running security checks
# - Running type checks
# - Code linting and formatting checks
#
# Usage: ./tests_runner.sh [OPTIONS]
# Options:
#   --coverage      Generate coverage report
#   --lint          Run linting checks
#   --security      Run security checks
#   --type-check    Run type checking
#   --full          Run complete test suite (all checks)
#   -v, --verbose   Verbose output
#   -h, --help      Show this help message
################################################################################

set -o pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Flags
COVERAGE=false
LINT=false
SECURITY=false
TYPE_CHECK=false
FULL=false
VERBOSE=false

# Track overall success
OVERALL_SUCCESS=true

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

################################################################################
# Helper Functions
################################################################################

print_header() {
    local message="$1"
    echo -e "\n${BOLD}${BLUE}$(printf '=%.0s' {1..60})${NC}"
    printf "${BOLD}${BLUE}%*s${NC}\n" $(( (${#message} + 60) / 2 )) "$message"
    echo -e "${BOLD}${BLUE}$(printf '=%.0s' {1..60})${NC}\n"
}

print_section() {
    echo -e "\n${CYAN}▶ $1${NC}"
}

print_success() {
    echo -e "${GREEN}[✓] $1${NC}"
}

print_error() {
    echo -e "${RED}[✗] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[?] $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

run_command() {
    local cmd="$1"
    local description="$2"
    
    print_section "$description"
    
    if [ "$VERBOSE" = true ]; then
        print_info "Command: $cmd"
        eval "$cmd"
        local exit_code=$?
    else
        eval "$cmd" > /dev/null 2>&1
        local exit_code=$?
    fi
    
    if [ $exit_code -eq 0 ]; then
        print_success "$description completed successfully"
        return 0
    else
        print_error "$description failed with exit code $exit_code"
        return 1
    fi
}

check_command_exists() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}Error: '$1' is not installed. Please install it first.${NC}"
        return 1
    fi
    return 0
}

################################################################################
# Test Functions
################################################################################

run_all_tests() {
    print_header "Running All Tests"
    
    local cmd="pytest tests/"
    [ "$VERBOSE" = true ] && cmd="$cmd -vv" || cmd="$cmd -v"
    
    run_command "$cmd" "All tests" || OVERALL_SUCCESS=false
}

run_coverage_report() {
    print_header "Generating Coverage Report"
    
    local cmd="pytest tests/ --cov=vulnradar --cov-report=html --cov-report=term-missing --cov-report=xml --cov-branch"
    
    if run_command "$cmd" "Coverage report"; then
        print_success "Coverage report generated in htmlcov/index.html"
        [ -f "coverage.xml" ] && print_success "XML coverage report generated"
    else
        OVERALL_SUCCESS=false
    fi
}

run_linting() {
    print_header "Running Code Linting & Formatting Checks"
    
    local linting_success=true
    
    # Flake8
    check_command_exists "flake8" || return 1
    print_section "Flake8 linting"
    if flake8 vulnradar --max-line-length=120 > /dev/null 2>&1; then
        print_success "Flake8 linting passed"
    else
        print_error "Flake8 linting failed"
        [ "$VERBOSE" = true ] && flake8 vulnradar --max-line-length=120
        linting_success=false
    fi
    
    # Black formatting check
    check_command_exists "black" || return 1
    print_section "Black formatting check"
    if black vulnradar --check > /dev/null 2>&1; then
        print_success "Black formatting check passed"
    else
        print_error "Black formatting check failed"
        [ "$VERBOSE" = true ] && black vulnradar --check
        print_info "Run 'black vulnradar' to auto-format code"
        linting_success=false
    fi
    
    # isort check
    check_command_exists "isort" || return 1
    print_section "Import sorting check"
    if isort vulnradar --profile black --check-only > /dev/null 2>&1; then
        print_success "Import sorting check passed"
    else
        print_error "Import sorting check failed"
        [ "$VERBOSE" = true ] && isort vulnradar --profile black --check-only
        print_info "Run 'isort vulnradar --profile black' to auto-sort imports"
        linting_success=false
    fi
    
    [ "$linting_success" = true ] || OVERALL_SUCCESS=false
}

run_security_checks() {
    print_header "Running Security Checks"
    
    local security_success=true
    
    # Bandit
    check_command_exists "bandit" || return 1
    print_section "Bandit security scan"
    if bandit -r vulnradar -f json --output bandit-report.json > /dev/null 2>&1; then
        print_success "Bandit security scan completed"
        [ -f "bandit-report.json" ] && print_success "Bandit report generated: bandit-report.json"
    else
        print_error "Bandit security scan had issues"
        [ "$VERBOSE" = true ] && bandit -r vulnradar
        security_success=false
    fi
    
    # Safety
    check_command_exists "safety" || {
        print_warning "Safety not installed, skipping dependency check"
        return 0
    }
    
    print_section "Safety dependency check"
    if safety scan > /dev/null 2>&1; then
        print_success "Safety dependency check passed"
    else
        print_warning "Safety dependency check found potential issues"
        [ "$VERBOSE" = true ] && safety scan
    fi
    
    [ "$security_success" = true ] || OVERALL_SUCCESS=false
}

run_type_checking() {
    print_header "Running Type Checking"
    
    check_command_exists "mypy" || return 1
    
    local cmd="mypy vulnradar --install-types --ignore-missing-imports"
    [ "$VERBOSE" = true ] && cmd="$cmd --show-error-codes --pretty"
    
    if eval "$cmd" > /dev/null 2>&1; then
        print_success "Type checking passed"
    else
        print_error "Type checking found issues"
        [ "$VERBOSE" = true ] || eval "$cmd"
        OVERALL_SUCCESS=false
    fi
}

run_full_suite() {
    print_header "Running Full Test Suite"
    
    run_coverage_report
    echo ""
    run_linting
    echo ""
    run_type_checking
    echo ""
    run_security_checks
}

################################################################################
# Help and Argument Parsing
################################################################################

show_help() {
    cat <<EOF
${BOLD}VulnRadar Test Runner${NC}

${BOLD}USAGE:${NC}
  $(basename "$0") [OPTIONS]

${BOLD}OPTIONS:${NC}
  --coverage       Generate coverage report (pytest with coverage)
  --lint           Run linting checks (flake8, black, isort)
  --security       Run security checks (bandit, safety)
  --type-check     Run type checking (mypy)
  --full           Run complete test suite (all checks)
  -v, --verbose    Verbose output (shows full command output)
  -h, --help       Show this help message

${BOLD}EXAMPLES:${NC}
  $(basename "$0")                    # Run all tests
  $(basename "$0") --coverage         # Generate coverage report
  $(basename "$0") --lint --type-check # Lint and type check
  $(basename "$0") --full --verbose   # Full suite with verbose output
  $(basename "$0") --security         # Run security checks only

EOF
}

################################################################################
# Main
################################################################################

main() {
    # Parse arguments
    if [ $# -eq 0 ]; then
        # No arguments, run all tests
        run_all_tests
    else
        while [[ $# -gt 0 ]]; do
            case $1 in
                --coverage)
                    COVERAGE=true
                    shift
                    ;;
                --lint)
                    LINT=true
                    shift
                    ;;
                --security)
                    SECURITY=true
                    shift
                    ;;
                --type-check)
                    TYPE_CHECK=true
                    shift
                    ;;
                --full)
                    FULL=true
                    shift
                    ;;
                -v|--verbose)
                    VERBOSE=true
                    shift
                    ;;
                -h|--help)
                    show_help
                    exit 0
                    ;;
                *)
                    echo -e "${RED}Unknown option: $1${NC}"
                    show_help
                    exit 1
                    ;;
            esac
        done
        
        # Run selected checks
        if [ "$FULL" = true ]; then
            run_full_suite
        else
            [ "$COVERAGE" = true ] && run_coverage_report && echo ""
            [ "$LINT" = true ] && run_linting && echo ""
            [ "$TYPE_CHECK" = true ] && run_type_checking && echo ""
            [ "$SECURITY" = true ] && run_security_checks && echo ""
        fi
    fi
    
    # Print final status
    echo -e "\n${BOLD}${BLUE}$(printf '=%.0s' {1..60})${NC}"
    if [ "$OVERALL_SUCCESS" = true ]; then
        echo -e "${BOLD}${GREEN}✓ All tests and checks passed!${NC}"
    else
        echo -e "${BOLD}${YELLOW}⚠ Some tests or checks failed${NC}"
    fi
    echo -e "${BOLD}${BLUE}$(printf '=%.0s' {1..60})${NC}\n"
    
    # Exit with appropriate code
    [ "$OVERALL_SUCCESS" = true ] && exit 0 || exit 1
}

# Run main function
main "$@"
