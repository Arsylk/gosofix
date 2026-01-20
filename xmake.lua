set_project("gosofix")
set_version("0.0.4")

add_rules("mode.debug", "mode.release")

-- CLI Binary
target("gosofix")
    set_kind("binary")
    set_targetdir("dist")
    on_build(function (target)
        local ldflags = is_mode("release") and "-s -w" or ""
        os.execv("go", {"build", "-trimpath", "-ldflags=" .. ldflags, "-o", target:targetfile(), "cmd/main.go"})
    end)

-- Shared Library
target("libgosofix")
    set_kind("shared")
    set_basename("gosofix")
    set_targetdir("dist")
    on_build(function (target)
        local ldflags = is_mode("release") and "-s -w" or ""
        os.execv("go", {"build", "-buildmode=c-shared", "-trimpath", "-ldflags=" .. ldflags, "-o", target:targetfile(), "cmd/main.go"})
    end)

-- DL Test Utility (C)
target("test_dl")
    set_kind("binary")
    add_files("tests/test_dl.c")
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
        local test_dl = path.join("dist", "test_dl")
        local sample_so = "tests/libjiagu_64.so_dump_0x7104417000.so"

        print("\n\27[1m=== Phase 1: Structural Verification ===\27[0m")
        log_info("verify:file", "path", gosofix)
        os.execv("file", { gosofix })

        log_info("verify:symbols", "target", "libgosofix.so")
        local libgosofix_path = path.join("dist", "libgosofix.so")
        local out = os.iorun("nm -D " .. libgosofix_path)
        if out:find("FixElf") then
            log_success("symbol found: FixElf")
        else
            error("FixElf not found in " .. libgosofix_path)
        end

        print("\n\27[1m=== Phase 2: Functional Testing ===\27[0m")
        log_info("test:exec", "cmd", gosofix, "arg", sample_so)
        os.execv(gosofix, { sample_so })

        log_info("test:dlopen", "cmd", test_dl, "lib", libgosofix_path)
        os.execv(test_dl, { libgosofix_path, sample_so })

        print("")
        log_success("All tests and verification passed!")
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
