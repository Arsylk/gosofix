set_project("gosofix")
set_version("0.0.5")

add_rules("mode.debug", "mode.release")

-- CLI Binary
-- Built entirely by the Go toolchain via on_build, so the target is "phony":
-- this stops xmake from inferring a Go/cgo toolchain (and demanding an
-- uninstallable "cgo" package) for a target it does not compile itself.
target("gosofix")
set_kind("phony")
on_build(function(target)
	local ldflags = is_mode("release") and "-s -w" or ""
	os.mkdir("dist")
	os.execv("go", { "build", "-trimpath", "-ldflags=" .. ldflags, "-o", "dist/gosofix", "cmd/main.go" })
	print("[+] built dist/gosofix")
end)

-- Shared Library (c-shared; go drives cgo through the host C compiler)
target("libgosofix")
set_kind("phony")
on_build(function(target)
	local ldflags = is_mode("release") and "-s -w" or ""
	os.mkdir("dist")
	os.execv(
		"go",
		{
			"build",
			"-buildmode=c-shared",
			"-trimpath",
			"-ldflags=" .. ldflags,
			"-o",
			"dist/libgosofix.so",
			"cmd/main.go",
		}
	)
	print("[+] built dist/libgosofix.so (+ dist/libgosofix.h)")
end)

task("install")
set_menu({
	usage = "xmake install",
	description = "Install generated binaries to /opt/github/.bin/ with hash comparison",
})
on_run(function()
	os.run("xmake build -a")
	local bin_dir = "/opt/github/.bin"
	os.vrunv("sudo", { "mkdir", "-p", bin_dir })
	local dist_dir = path.join(os.projectdir(), "dist")
	for _, file in ipairs(os.files(path.join(dist_dir, "*"))) do
		local filename = path.filename(file)
		local dest = path.join(bin_dir, filename)

		if os.isfile(dest) then
			local old_hash = hash.sha256(dest)
			local new_hash = hash.sha256(file)
			if old_hash ~= new_hash then
				os.vrunv("sudo", { "rm", "-f", dest })
				os.vrunv("sudo", { "cp", file, dest })
				os.vrunv("sudo", { "chmod", "755", dest })
				cprintf("${yellow}!${clear} changed: ${dim}%s${clear}\n", dest)
			else
				cprintf("${blue}·${clear} unchanged: ${dim}%s${clear}\n", dest)
			end
		else
			os.vrunv("sudo", { "cp", file, dest })
			os.vrunv("sudo", { "chmod", "755", dest })
			cprintf("${green}✓${clear} installed: ${dim}%s${clear}\n", dest)
		end
	end
end)

-- DL Test Utility (C)
target("test_dl")
set_kind("binary")
add_files("samples/test_dl.c")
add_syslinks("dl")
set_targetdir("dist")

-- Unified Test Task
task("test")
on_run(function()
	local function log_info(msg, ...)
		local args = { ... }
		local formatted_msg = string.format("\27[1;38;5;86m[+]\27[0m %s", msg)
		for i = 1, #args, 2 do
			formatted_msg = formatted_msg
				.. string.format(" \27[38;5;243m%s=\27[0m\27[38;5;147m%s\27[0m", args[i], args[i + 1])
		end
		print(formatted_msg)
	end

	local function log_success(msg)
		print(string.format("\27[1;38;5;86m[+]\27[0m %s", msg))
	end

	log_info("xmake:build", "status", "starting")
	os.exec("xmake build")

	local gosofix = path.join("dist", "gosofix")
	local libgosofix = path.join("dist", "libgosofix.so")

	-- Phase 1: Binary verification
	print("\n\27[1m=== Phase 1: Binary Verification ===\27[0m")
	log_info("verify:file", "path", gosofix)
	os.execv("file", { gosofix })

	log_info("verify:symbols", "target", "libgosofix.so")
	local out = os.iorun("nm -D " .. libgosofix)
	if out:find("FixElf") then
		log_success("symbol found: FixElf")
	else
		error("FixElf not found in " .. libgosofix)
	end

	-- Phase 2: Go unit + integration tests. The Go suite owns the sample
	-- manifest and writes every reconstructed output into a temporary directory.
	print("\n\27[1m=== Phase 2: Go Test Suite ===\27[0m")
	log_info("test:go", "package", "./...")
	os.execv("go", { "test", "./...", "-count=1" })
	log_success("go test passed")

	-- Phase 3: dlopen test
	print("\n\27[1m=== Phase 3: Library Interface ===\27[0m")
	local test_dl = path.join("dist", "test_dl")
	local dl_output = path.join("dist", "test_dl_output.so")
	log_info("test:dlopen", "lib", libgosofix)
	os.execv(test_dl, { libgosofix, "samples/libjiagu.so_dump_0x759b2b2000.so", dl_output })
	os.rm(dl_output)

	print("")
	log_success("all tests passed")
end)
set_menu({
	usage = "xmake test",
	description = "Run all tests and verify build",
})

set_menu({
	usage = "xmake [task] [options]",
	description = "Build system for gosofix CLI and Library",
	options = {
		{ "b", "build", "k", nil, "Build targets" },
		{ "c", "clean", "k", nil, "Clean build artifacts" },
		{ "t", "test", "k", nil, "Run tests and verification" },
	},
})
