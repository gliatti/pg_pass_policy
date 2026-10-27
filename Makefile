EXTENSION    = pg_pass_policy
EXTVERSION   = 1.0
MODULE_big   = pg_pass_policy
OBJS         = src/pg_pass_policy.o src/policy.o src/lockout.o src/worker.o
PG_CPPFLAGS  = -I$(srcdir)/src
DATA         = sql/pg_pass_policy--$(EXTVERSION).sql
PGFILEDESC   = "pg_pass_policy - password policy, rotation and lockout for roles"

REGRESS      = $(notdir $(basename $(wildcard test/sql/*.sql)))
REGRESS_OPTS = --inputdir=test --outputdir=test --temp-config=test/pg_pass_policy.conf --temp-instance=test/tmp_check
EXTRA_CLEAN  = test/results test/tmp_check

PG_CONFIG   ?= pg_config
PGXS        := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

# make check n'est pas supporté par PGXS : "make test" installe puis lance
# pg_regress sur une instance temporaire (shared_preload_libraries oblige).
test: install installcheck
	$(MAKE) -C . shellcheck-tests

shellcheck-tests:
	PG_CONFIG=$(PG_CONFIG) bash test/shell/run-all.sh

.PHONY: test shellcheck-tests
