# Base image mirror

CI pulls some base images from `ghcr.io/salcyberaware/mirror`, a copy of the same digests, because public.ecr.aws often answers GitHub runners with `429 Data limit exceeded`. The mirror is kept by the **Mirror base images** workflow in PromptShield, which reads `main` of this repo every Thursday. PromptShield's `docs/BASE_IMAGE_MIRROR.md` describes it in full. This file covers the one rule that applies to this repo's workflows.

## Mirror image lines in workflows

A service container, such as the test Postgres, starts before any step runs, so CI cannot swap its image the way the container job swaps a FROM line. A workflow `image:` line may therefore name the mirror directly. It must be one line, with a comment that names the real upstream image:tag:

```yaml
image: ghcr.io/salcyberaware/mirror/postgres:18@sha256:<digest> # mirror of public.ecr.aws/docker/library/postgres:18
```

- Both scripts in `.github/scripts` read the line as a pin of the upstream image:tag in the comment, at the digest on the line. The base image watch compares that digest with the upstream tag's current digest. The mirror workflow copies the upstream image to the mirror and checks that the digests match. Both work as they do for any other pin.
- The name and tag on the line must be the mirror name for that upstream: `ghcr.io/salcyberaware/mirror/` plus the image path after the registry, without `docker/library/` (or `library/` on Docker Hub), and the same tag. So `adobe/s3mock:5.2.3` becomes `ghcr.io/salcyberaware/mirror/adobe/s3mock:5.2.3`.
- The comment may also carry the digest (`# mirror of <image>:<tag>@sha256:<digest>`). It must then be the digest on the line.
- A mirror line with no `# mirror of` comment, a name or tag that does not match the comment, or a digest that disagrees fails both the base image watch and the mirror run. The log names the line and the reason.
- Only workflow `image:` lines work this way. A Dockerfile FROM line is read as before.
- Nothing moves a mirror line's digest for you. When the base image watch opens an issue for the upstream image:tag, make sure the new digest is in the mirror (run **Mirror base images** in PromptShield), then change the digest on the line.
