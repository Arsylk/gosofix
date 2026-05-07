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

        local function log_fail(msg, ...)
            local args = { ... }
            local formatted_msg = string.format("\27[1;38;5;204m[x]\27[0m %s", msg)
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

        -- Phase 2: Multi-sample regression
        -- Selected for diversity in size, relocation types, and structure
        print("\n\27[1m=== Phase 2: Sample Regression ===\27[0m")
        local samples = {
            { file = "samples/libjiagu.so_dump_0x759b2b2000.so",            tag = "jiagu-3MB-rela+jmprel" },
            { file = "samples/libdexprotector.so_dump_0x6ddc6d8000.so",      tag = "dexprotect-412K-rela+hash" },
            { file = "samples/saitcza.so_dump_0x76c8436000.so",              tag = "obfuscated-2.3MB" },
            { file = "samples/libstubiest.so_dump_0x7572b00000.so",          tag = "minimal-252K" },
            { file = "samples/libSt9w.so_dump_0x7366c6e000.so",             tag = "corrupt-shdrs-1.4MB" },
            { file = "samples/libriskdetector.so_dump_0x6f3d8f4000.so",      tag = "riskdetector-569K" },
            { file = "samples/libhunter.so_dump_0x6bfda14000.so",            tag = "hunter-3.8MB" },
            { file = "samples/libuseard.so_dump_0x71fcfa8000.so",            tag = "useard-287K" },
        }

        local passed, failed = 0, 0
        for _, s in ipairs(samples) do
            log_info("test:fix", "sample", s.tag)
            local sample_ok = true

            try {
                function()
                    os.execv(gosofix, { s.file })
                end,
                catch {
                    function(e)
                        log_fail("test:fix FAILED", "sample", s.tag, "err", tostring(e))
                        failed = failed + 1
                        sample_ok = false
                    end
                }
            }

            if sample_ok then
                local outpath = s.file:gsub("(%.[^%.]+)$", "_fix%1")
                if not os.isfile(outpath) then
                    outpath = s.file .. "_fix"
                end

                if os.isfile(outpath) then
                    try {
                        function()
                            os.execv("readelf", { "-h", outpath })
                            passed = passed + 1
                        end,
                        catch {
                            function(e)
                                log_fail("test:readelf FAILED", "sample", s.tag)
                                failed = failed + 1
                            end
                        }
                    }
                else
                    log_fail("test:output missing", "sample", s.tag)
                    failed = failed + 1
                end
            end
        end

        -- Phase 3: Go unit + integration tests
        print("\n\27[1m=== Phase 3: Go Test Suite ===\27[0m")
        log_info("test:go", "package", "./test/")
        try {
            function()
                os.execv("go", { "test", "./test/", "-count=1" })
            end,
            catch {
                function(e)
                    log_fail("test:go FAILED", "err", tostring(e))
                    os.exit(1)
                end
            }
        }
        log_success("go test passed")

        -- Phase 4: dlopen test
        print("\n\27[1m=== Phase 4: Library Interface ===\27[0m")
        local test_dl = path.join("dist", "test_dl")
        log_info("test:dlopen", "lib", libgosofix)
        os.execv(test_dl, { libgosofix, samples[1].file })

        -- Summary
        print("")
        if failed == 0 then
            log_success(string.format("All tests passed! (%d/%d samples)", passed, #samples))
        else
            raise(string.format("%d/%d samples failed", failed, #samples))
        end
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
