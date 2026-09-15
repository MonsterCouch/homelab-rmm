// Package web embeds the built single-page application. Run `npm run build`
// in this directory (or tools/build.ps1 at the repo root) to refresh dist/.
package web

import "embed"

//go:embed all:dist
var Dist embed.FS
