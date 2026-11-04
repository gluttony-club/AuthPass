// genicon creates the monochrome tray template asset.
package main

import (
	"image"
	"image/color"
	"image/png"
	"os"
)

func main() {
	m := image.NewNRGBA(image.Rect(0, 0, 22, 22))
	for y := 3; y < 19; y++ {
		for x := 5; x < 17; x++ {
			if y >= 10 || (y < 11 && (x == 6 || x == 7 || x == 14 || x == 15 || y == 3 || y == 4)) {
				m.Set(x, y, color.NRGBA{A: 255})
			}
		}
	}
	f, e := os.Create("cmd/authpass/icon.png")
	if e != nil {
		panic(e)
	}
	defer f.Close()
	if e = png.Encode(f, m); e != nil {
		panic(e)
	}
}
