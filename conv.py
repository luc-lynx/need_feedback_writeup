tmpl = "part%02d_raw_d"

with open("result.png", "wb") as fl:
	for i in range(0, 20):
		with open(tmpl % i, "rb") as f:
			m = f.read()
			pos = m.find(b'\r\n\r\n')
			fl.write(m[pos + 4:])
