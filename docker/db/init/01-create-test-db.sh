#!/bin/bash
# Creates the test and benchmark databases alongside the dev database on first boot.
set -e
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" <<-EOSQL
  CREATE DATABASE cybersec_test;
  CREATE DATABASE cybersec_bench;
EOSQL
