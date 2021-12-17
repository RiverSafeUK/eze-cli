# Overview

Provides a simple developer linux box for testing

# Usage

build with

```bash
docker build --tag eze-dev .
```

cd to directory and use with

```bash
docker run -it -v $(pwd -W):/data eze-dev
```