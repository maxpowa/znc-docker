#! /usr/bin/env bash

# Options.
DATADIR="/znc-data"

if [ ! -f "${DATADIR}/modules/identserv.cpp" ]; then
  mkdir -p "${DATADIR}/modules"
  cp /identserv.cpp "${DATADIR}/modules/identserv.cpp"
fi

# Build modules from source.
if [ -d "${DATADIR}/modules" ]; then
  # Store current directory.
  cwd="$(pwd)"

  # Find module sources.
  modules=$(find "${DATADIR}/modules" -name "*.cpp")

  # Build modules.
  for module in $modules; do
    cd "$(dirname "$module")"
    /opt/znc/bin/znc-buildmod "$module"
  done

  # Go back to original directory.
  cd "$cwd"
fi

# Create default config if it doesn't exist
if [ ! -f "${DATADIR}/configs/znc.conf" ]; then
  mkdir -p "${DATADIR}/configs"
  cp /znc.conf.default "${DATADIR}/configs/znc.conf"
fi

# Make sure $DATADIR is owned by znc user. This effects ownership of the
# mounted directory on the host machine too.
chown -R znc:znc "$DATADIR"

# Start ZNC.
exec sudo -u znc /opt/znc/bin/znc --foreground --datadir="$DATADIR" $@
