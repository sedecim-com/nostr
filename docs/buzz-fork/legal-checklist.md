# Fork de Buzz · checklist Apache-2.0 (BUZZ-02)

Buzz se distribuye bajo **Apache License 2.0** (`LICENSE` de upstream). Obligaciones al redistribuir el
fork, en código fuente o como imagen de contenedor (§4 de la licencia):

- [ ] **4(a)** Incluir una copia de la licencia Apache-2.0 en el fork y en la imagen (`/usr/share/doc/buzz/LICENSE`).
- [ ] **4(b)** Marcar de forma visible los archivos modificados: cabecera `Modified by sedecim, <año>: <motivo>` y registro en `PATCHES.md` del fork.
- [ ] **4(c)** Conservar todos los avisos de copyright, patentes, marcas y atribución del código original.
- [ ] **4(d)** Si upstream incluye un `NOTICE`, redistribuirlo. Upstream no tiene `NOTICE` a `02c6309`; el fork añade uno propio (plantilla abajo).
- [ ] **§6 Marcas**: no usar "Buzz" ni "Block" como marca del producto. El branding propio corresponde a BUZZ-04. Se puede mencionar el origen de forma descriptiva ("basado en Block Buzz").
- [ ] Revisar las licencias de las dependencias del subset incluido (ADR 0002) con `cargo deny check licenses`; upstream ya tiene `deny.toml`.
- [ ] Publicar SBOM y provenance de la imagen (`buzz-image.yml` genera ambos).
- [ ] Revisión legal firmada (nombre, fecha) antes del primer release público del fork.

## Plantilla de `NOTICE` para el fork
```
sedecim Buzz fork
Copyright 2026 sedecim

This product includes software developed by Block, Inc. and the Buzz contributors
(https://github.com/block/buzz), licensed under the Apache License, Version 2.0.

Modifications by sedecim are listed in PATCHES.md and marked in each modified file.
```

## Relación con la licencia de este repositorio
Ver ADR 0001. Si este repositorio pasa a Apache-2.0, el régimen es el mismo en ambos. Si se mantiene
MIT, la combinación sigue siendo válida: el fork es una obra separada distribuida como imagen y este
repositorio no incorpora código de Buzz.
