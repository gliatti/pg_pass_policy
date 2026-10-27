# Image de test de pg_pass_policy pour une version majeure de PostgreSQL.
#   docker build -f docker/Dockerfile --build-arg PG_MAJOR=17 -t ppp-test:17 .
# Le contexte de construction est la racine du dépôt (voir docker/compose.yml).
# Images officielles vérifiées (docker manifest inspect, 2026-10) :
# postgres:14-bookworm … postgres:18-bookworm existent (18 existe aussi en trixie).
ARG PG_MAJOR=16
ARG DEBIAN_SUITE=bookworm
FROM postgres:${PG_MAJOR}-${DEBIAN_SUITE}

ARG PG_MAJOR
ENV PG_MAJOR=${PG_MAJOR} \
    PG_CONFIG=/usr/lib/postgresql/${PG_MAJOR}/bin/pg_config \
    PATH=/usr/lib/postgresql/${PG_MAJOR}/bin:${PATH}

# Les images officielles configurent déjà apt.postgresql.org (PGDG)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        "postgresql-server-dev-${PG_MAJOR}" \
 && rm -rf /var/lib/apt/lists/*

COPY . /src
WORKDIR /src

# Compilation et installation (root) ; les tests tournent ensuite en postgres
# (initdb et pg_regress refusent root).
RUN make clean \
 && make \
 && make install \
 && chown -R postgres:postgres /src

USER postgres
ENTRYPOINT []
CMD ["bash", "docker/test-in-container.sh"]
