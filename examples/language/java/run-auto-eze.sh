#!/usr/bin/env bash
docker run -t -v $(pwd -W):/data eze-cli test --force-autoscan