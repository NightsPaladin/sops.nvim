-- File: lua/sops/init.lua
local M = {}

local config = {
  skip_failed_auth = false,
}

-- Store SOPS metadata and extracted keys for each buffer
local sops_metadata = {}
local sops_keys = {}

function M.setup(user_config)
  config = vim.tbl_deep_extend("force", config, user_config or {})

  vim.api.nvim_create_user_command("SopsEncrypt", function()
    local bufnr = vim.api.nvim_get_current_buf()
    M.encrypt_file(bufnr)
  end, { desc = "Encrypt the current buffer with sops" })

  vim.api.nvim_create_user_command("SopsDecrypt", function()
    local bufnr = vim.api.nvim_get_current_buf()
    M.decrypt_file(bufnr)
  end, { desc = "Decrypt the current buffer with sops" })

  vim.api.nvim_create_user_command("SopsCleanup", function()
    local bufnr = vim.api.nvim_get_current_buf()
    M.cleanup_keys(bufnr)
  end, { desc = "Clean up stored SOPS keys for current buffer" })

  vim.api.nvim_create_user_command("SopsReload", function()
    local path = vim.api.nvim_buf_get_name(0)
    if path ~= "" then
      vim.cmd("edit!")
    end
  end, { desc = "Reload and decrypt SOPS file" })

  vim.api.nvim_create_autocmd("BufReadPost", {
    pattern = "*",
    callback = function(args)
      vim.schedule(function()
        M.decrypt_file(args.buf)
      end)
    end,
  })

  -- vim.api.nvim_create_autocmd("BufWritePre", {
  --   pattern = "*",
  --   callback = function(args)
  --     -- Only handle files that have SOPS metadata
  --     if sops_metadata[args.buf] and sops_keys[args.buf] then
  --       M.encrypt_file(args.buf)
  --     end
  --   end,
  -- })

  vim.api.nvim_create_autocmd("BufWriteCmd", {
    pattern = "*",
    callback = function(args)
      local bufnr = args.buf
      -- Only handle files that have SOPS metadata
      if sops_metadata[bufnr] and sops_keys[bufnr] then
        local messages = {}
        -- Temporarily intercept notifications
        local old_notify = vim.notify
        vim.notify = function(msg, level, opts)
          table.insert(messages, { msg, level, opts })
        end

        M.encrypt_file(args.buf)
        vim.bo[bufnr].modified = false

        -- Restore notify and send messages *after* write finishes
        vim.notify = old_notify
        vim.schedule(function()
          for _, m in ipairs(messages) do
            vim.notify(m[1], m[2], m[3])
          end
        end)
      else
        vim.cmd("write!")
      end
    end,
  })

  -- Clean up metadata when buffer is deleted
  vim.api.nvim_create_autocmd("BufDelete", {
    pattern = "*",
    callback = function(args)
      sops_metadata[args.buf] = nil
      sops_keys[args.buf] = nil
    end,
  })
end

local function is_sops_encrypted(bufnr)
  local line_count = vim.api.nvim_buf_line_count(bufnr)

  -- For performance on large files, check the last 200 lines first (where SOPS metadata usually is)
  local start_line = math.max(0, line_count - 200)
  local lines = vim.api.nvim_buf_get_lines(bufnr, start_line, -1, false)

  for _, line in ipairs(lines) do
    if line:match("^sops:") then
      return true
    end
  end

  -- If not found in the last 200 lines, check the first 100 lines as fallback
  if start_line > 0 then
    local first_lines = vim.api.nvim_buf_get_lines(bufnr, 0, math.min(100, line_count), false)

    for _, line in ipairs(first_lines) do
      if line:match("^sops:") then
        return true
      end
    end
  end

  return false
end

local function extract_sops_metadata(bufnr)
  local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
  local metadata = {}
  local in_sops_section = false

  for _, line in ipairs(lines) do
    if line:match("^sops:") then
      in_sops_section = true
      table.insert(metadata, line)
    elseif in_sops_section then
      if line:match("^%s") or line:match("^%-") then
        -- Still in SOPS section (indented or list item)
        table.insert(metadata, line)
      else
        -- End of SOPS section
        break
      end
    end
  end

  return metadata
end

local function extract_sops_keys(metadata)
  local keys = {
    kms = {},
    gcp_kms = {},
    azure_kv = {},
    pgp = {},
    age = {},
    hc_vault_transit_uri = {},
  }

  local in_sops_section = false
  local current_section = nil

  for _, line in ipairs(metadata) do
    if line:match("^sops:") then
      in_sops_section = true
    elseif in_sops_section then
      if line:match("^%s") then
        -- Check for section headers
        if line:match("^%s+kms:") then
          current_section = "kms"
        elseif line:match("^%s+gcp_kms:") then
          current_section = "gcp_kms"
        elseif line:match("^%s+azure_kv:") then
          current_section = "azure_kv"
        elseif line:match("^%s+pgp:") then
          current_section = "pgp"
        elseif line:match("^%s+age:") then
          current_section = "age"
        elseif line:match("^%s+hc_vault:") then
          current_section = nil -- Handle separately
        elseif current_section and line:match("^%s+%-") then
          -- Extract the actual key value from list items
          local key_value = line:match("^%s+%-%s*(.+)")
          if key_value then
            -- Handle different key formats
            if current_section == "kms" then
              -- Extract ARN from kms entries
              local arn = key_value:match("arn:%s*([%w%p]+)")
              if arn then
                table.insert(keys[current_section], "arn:" .. arn)
              end
            elseif current_section == "pgp" then
              -- Extract fingerprint from pgp entries
              local fp = key_value:match("fp:%s*([%w]+)")
              if fp then
                table.insert(keys[current_section], fp)
              end
            elseif current_section == "age" then
              -- Extract age key
              local age_key = key_value:match("(age1[a-z0-9]+)")
              if age_key then
                table.insert(keys[current_section], age_key)
              end
            elseif current_section == "gcp_kms" then
              -- Extract GCP KMS resource ID
              local gcp_key = key_value:match("resource_id:%s*['\"]?([^'\"]+)['\"]?")
              if gcp_key then
                table.insert(keys[current_section], gcp_key)
              end
            elseif current_section == "azure_kv" then
              -- Extract Azure Key Vault URL
              local vault_url = key_value:match("vault_url:%s*['\"]?([^'\"]+)['\"]?")
              local name = key_value:match("name:%s*['\"]?([^'\"]+)['\"]?")
              local version = key_value:match("version:%s*['\"]?([^'\"]+)['\"]?")
              if vault_url and name then
                local azure_url = vault_url .. "/keys/" .. name
                if version then
                  azure_url = azure_url .. "/" .. version
                end
                table.insert(keys[current_section], azure_url)
              end
            end
          end
        end
      else
        break
      end
    end
  end

  -- Process hc_vault section separately for transit URIs
  local in_hc_vault_section = false
  local current_vault_config = {}

  for _, line in ipairs(metadata) do
    if line:match("^%s*hc_vault:%s*$") then
      in_hc_vault_section = true
    elseif in_hc_vault_section then
      if line:match("^%s") then
        if line:match("^%s*%-") then
          -- Process previous config if complete
          if
            current_vault_config.vault_address
            and current_vault_config.engine_path
            and current_vault_config.key_name
          then
            local hc_vault_transit_uri = current_vault_config.vault_address
              .. "/v1/"
              .. current_vault_config.engine_path
              .. "/keys/"
              .. current_vault_config.key_name
            table.insert(keys.hc_vault_transit_uri, hc_vault_transit_uri)
          end
          current_vault_config = {}
          local vault_addr = line:match("vault_address:%s*['\"]?(https://[%w%p]+)['\"]?")
          if vault_addr then
            current_vault_config.vault_address = vault_addr
          end
        else
          local engine_path = line:match("engine_path:%s*['\"]?([%w%-_/]+)['\"]?")
          if engine_path then
            current_vault_config.engine_path = engine_path
          end
          local key_name = line:match("key_name:%s*['\"]?([%w%-_/]+)['\"]?")
          if key_name then
            current_vault_config.key_name = key_name
          end
        end
      else
        -- End of hc_vault section, process any remaining config
        if
          current_vault_config.vault_address
          and current_vault_config.engine_path
          and current_vault_config.key_name
        then
          local hc_vault_transit_uri = current_vault_config.vault_address
            .. "/v1/"
            .. current_vault_config.engine_path
            .. "/keys/"
            .. current_vault_config.key_name
          table.insert(keys.hc_vault_transit_uri, hc_vault_transit_uri)
        end
        in_hc_vault_section = false
        current_vault_config = {}
      end
    end
  end

  -- Handle case where file ends while in hc_vault section
  if
    in_hc_vault_section
    and current_vault_config.vault_address
    and current_vault_config.engine_path
    and current_vault_config.key_name
  then
    local hc_vault_transit_uri = current_vault_config.vault_address
      .. "/v1/"
      .. current_vault_config.engine_path
      .. "/keys/"
      .. current_vault_config.key_name
    table.insert(keys.hc_vault_transit_uri, hc_vault_transit_uri)
  end

  return keys
end

local function extract_vault_address(bufnr)
  local lines = vim.api.nvim_buf_get_lines(bufnr, 0, math.min(100, vim.api.nvim_buf_line_count(bufnr)), false)
  for _, line in ipairs(lines) do
    local addr = line:match("address:%s*['\"]?(https://[%w%p]+)['\"]?")
    if addr then
      return addr
    end
  end
  return nil
end

local function get_vault_token(addr)
  -- Try to read token from vault CLI (respects token helper)
  local env = { VAULT_ADDR = addr }
  local result = vim.system({ "vault", "print", "token" }, { env = env }):wait()

  if result.code == 0 and result.stdout then
    local lines = vim.split(result.stdout, "\n")
    local token = lines[1] and lines[1]:match("^%s*(.-)%s*$") -- trim whitespace
    if token and token ~= "" then
      return token
    end
  end

  -- If vault print token fails, assume token helper will handle it
  return "token-helper-managed"
end

local function detect_key_backends(bufnr)
  local keys = { aws = false, gcp = false, azure = false, pgp = false, vault = false, age = false }
  local lines = vim.api.nvim_buf_get_lines(bufnr, 0, math.min(300, vim.api.nvim_buf_line_count(bufnr)), false)
  for _, line in ipairs(lines) do
    if line:match("arn:aws:kms:") then
      keys.aws = true
    end
    if line:match("projects/[%w%-]+/locations/[%w%-]+/keyRings") then
      keys.gcp = true
    end
    if line:match("azure:keyvault") or line:match("vault.azure.net") then
      keys.azure = true
    end
    if line:match("pgp:") or line:match("pgpkeys:") or line:match("PGP PUBLIC KEY BLOCK") then
      keys.pgp = true
    end
    if line:match("vault:") or line:match("address:") then
      keys.vault = true
    end
    if line:match("age1[a-z0-9]+") then
      keys.age = true
    end
  end
  return keys
end

local function check_aws_auth()
  local result = vim.system({ "aws", "sts", "get-caller-identity" }):wait()
  return result.code == 0
end

local function check_gcp_auth()
  local result = vim.system({ "gcloud", "auth", "list", "--filter=status:ACTIVE", "--format=value(account)" }):wait()
  if result.code == 0 and result.stdout then
    local lines = vim.split(result.stdout, "\n", { trimempty = true })
    return #lines > 0
  end
  return false
end

local function check_azure_auth()
  local result = vim.system({ "az", "account", "show" }):wait()
  return result.code == 0
end

local function check_pgp_keys()
  local result = vim.system({ "gpg", "--list-secret-keys" }):wait()
  if result.code == 0 and result.stdout then
    local lines = vim.split(result.stdout, "\n", { trimempty = true })
    return #lines > 0
  end
  return false
end

local function check_age_keys()
  -- Check if age keys are available (either via SOPS_AGE_KEY_FILE or SOPS_AGE_KEY env vars)
  local age_key_file = vim.env.SOPS_AGE_KEY_FILE
  if age_key_file and vim.fn.filereadable(age_key_file) == 1 then
    return true
  end

  local age_key = vim.env.SOPS_AGE_KEY
  if age_key and age_key ~= "" then
    return true
  end

  -- Check default age key file location
  local home = vim.env.HOME
  if home then
    local default_key_file = home .. "/.config/sops/age/keys.txt"
    if vim.fn.filereadable(default_key_file) == 1 then
      return true
    end
  end

  return false
end

function M.decrypt_file(bufnr)
  local path = vim.api.nvim_buf_get_name(bufnr)
  if path == "" then
    -- vim.notify("[sops.nvim] No file path found for buffer", vim.log.levels.DEBUG)
    return
  end

  if not is_sops_encrypted(bufnr) then
    -- vim.notify("[sops.nvim] File is not SOPS encrypted: " .. path, vim.log.levels.DEBUG)
    return
  end

  vim.notify("[sops.nvim] Decrypting: " .. vim.fn.fnamemodify(path, ":t"), vim.log.levels.INFO)

  -- Extract and store SOPS metadata before decryption
  local metadata = extract_sops_metadata(bufnr)
  -- vim.notify("[sops.nvim] Extracted " .. #metadata .. " lines of metadata", vim.log.levels.DEBUG)

  if #metadata > 0 then
    sops_metadata[bufnr] = metadata
    -- vim.notify("[sops.nvim] Stored metadata for buffer " .. bufnr, vim.log.levels.DEBUG)

    -- Extract keys from metadata for later encryption
    local keys = extract_sops_keys(metadata)
    sops_keys[bufnr] = keys

    -- local key_count = #keys.kms + #keys.gcp_kms + #keys.azure_kv + #keys.pgp + #keys.age + #keys.hc_vault_transit_uri
    -- vim.notify("[sops.nvim] Extracted " .. key_count .. " total keys", vim.log.levels.DEBUG)
  else
    vim.notify("[sops.nvim] No metadata extracted from file", vim.log.levels.WARN)
  end

  local keys = detect_key_backends(bufnr)
  local info = {}
  local ok = true

  if keys.aws then
    table.insert(info, "AWS KMS")
    if not check_aws_auth() then
      vim.notify("[sops.nvim] AWS auth failed", vim.log.levels.ERROR)
      ok = false
    end
  end

  if keys.gcp then
    table.insert(info, "GCP KMS")
    if not check_gcp_auth() then
      vim.notify("[sops.nvim] GCP auth failed", vim.log.levels.ERROR)
      ok = false
    end
  end

  if keys.azure then
    table.insert(info, "Azure KV")
    if not check_azure_auth() then
      vim.notify("[sops.nvim] Azure auth failed", vim.log.levels.ERROR)
      ok = false
    end
  end

  if keys.pgp then
    table.insert(info, "PGP")
    if not check_pgp_keys() then
      vim.notify("[sops.nvim] No PGP keys found", vim.log.levels.ERROR)
      ok = false
    end
  end

  if keys.age then
    table.insert(info, "Age")
    if not check_age_keys() then
      vim.notify("[sops.nvim] No Age keys found", vim.log.levels.ERROR)
      ok = false
    end
  end

  if keys.vault then
    table.insert(info, "Vault")
    local addr = extract_vault_address(bufnr)
    if addr then
      local env = { VAULT_ADDR = addr }
      local result = vim.system({ "vault", "token", "lookup" }, { env = env }):wait()
      if result.code ~= 0 then
        vim.notify("[sops.nvim] Vault authentication failed for " .. addr, vim.log.levels.ERROR)
        ok = false
      end
    end
  end

  vim.notify("[sops.nvim] Backends: " .. table.concat(info, ", "), vim.log.levels.INFO)
  if not ok then
    local msg = "[sops.nvim] Authentication failed for one or more backends."
    if config.skip_failed_auth then
      vim.notify(msg .. " Proceeding with decryption anyway.", vim.log.levels.WARN)
    else
      vim.notify(msg .. " Aborting decryption. Set skip_failed_auth = true to override.", vim.log.levels.WARN)
      return
    end
  end

  local env = {}
  -- Copy existing environment
  for k, v in pairs(vim.env) do
    env[k] = v
  end

  -- Add Vault environment variables if needed (use stored metadata)
  local stored_metadata = sops_metadata[bufnr]
  if stored_metadata then
    -- Extract vault address from stored metadata instead of current buffer
    local addr = nil
    local in_hc_vault_section = false

    for _, line in ipairs(stored_metadata) do
      if line:match("^%s*hc_vault:%s*$") then
        in_hc_vault_section = true
      elseif in_hc_vault_section and line:match("^%s") then
        if line:match("^%s*%-") then
          local found_addr = line:match("vault_address:%s*['\"]?(https://[%w%p]+)['\"]?")
          if found_addr then
            addr = found_addr
            break
          end
        end
      elseif in_hc_vault_section then
        break -- Left the hc_vault section
      end
    end

    if addr then
      env["VAULT_ADDR"] = addr
      local token = get_vault_token(addr)
      if token and token ~= "token-helper-managed" then
        env["VAULT_TOKEN"] = token
      end
      -- vim.notify("[sops.nvim] Using Vault address for decryption: " .. addr, vim.log.levels.DEBUG)
    end
  end

  local result = vim.system({ "sops", "-d", path }, { env = env }):wait()
  if result.code ~= 0 then
    local error_msg = result.stderr or "Unknown error"
    vim.notify("[sops.nvim] Decryption failed: " .. error_msg, vim.log.levels.ERROR)
    return
  end

  local output = result.stdout and vim.split(result.stdout, "\n") or {}
  vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, output)
  vim.bo[bufnr].modified = false
  vim.notify("[sops.nvim] Successfully decrypted", vim.log.levels.INFO)
end

function M.cleanup_keys(bufnr)
  local stored_keys = sops_keys[bufnr]
  if stored_keys then
    sops_keys[bufnr] = nil
    vim.notify("[sops.nvim] Cleaned up stored keys for buffer " .. bufnr, vim.log.levels.INFO)
  else
    vim.notify("[sops.nvim] No stored keys to clean up for this buffer", vim.log.levels.INFO)
  end
end

function M.encrypt_file(bufnr)
  local path = vim.api.nvim_buf_get_name(bufnr)
  -- vim.notify("[sops.nvim] Encrypt called for buffer " .. bufnr .. " with path: " .. (path or "nil"), vim.log.levels.DEBUG)

  if path == "" then
    -- vim.notify("[sops.nvim] No file path found for buffer", vim.log.levels.WARN)
    return
  end

  -- Check if we have stored SOPS metadata for this buffer
  local metadata = sops_metadata[bufnr]
  local keys = sops_keys[bufnr]

  if not metadata or #metadata == 0 or not keys then
    -- vim.notify("[sops.nvim] No SOPS metadata found for this buffer. File may not have been decrypted yet.", vim.log.levels.WARN)
    return
  end

  vim.notify("[sops.nvim] Encrypting: " .. vim.fn.fnamemodify(path, ":t"), vim.log.levels.INFO)

  local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)

  -- Create temporary file with buffer content
  local tmpfile = path .. ".tmp"
  local fd = io.open(tmpfile, "w")

  if not fd then
    vim.notify("[sops.nvim] Failed to create temporary file: " .. tmpfile, vim.log.levels.ERROR)
    return
  end

  fd:write(table.concat(lines, "\n"))
  fd:close()

  local env = {}
  -- Copy existing environment
  for k, v in pairs(vim.env) do
    env[k] = v
  end

  -- Add Vault environment variables if needed (use stored metadata)
  local addr = nil
  local in_hc_vault_section = false

  for _, line in ipairs(metadata) do
    if line:match("^%s*hc_vault:%s*$") then
      in_hc_vault_section = true
    elseif in_hc_vault_section and line:match("^%s") then
      if line:match("^%s*%-") then
        local found_addr = line:match("vault_address:%s*['\"]?(https://[%w%p]+)['\"]?")
        if found_addr then
          addr = found_addr
          break
        end
      end
    elseif in_hc_vault_section then
      break -- Left the hc_vault section
    end
  end

  if addr then
    env["VAULT_ADDR"] = addr
    local token = get_vault_token(addr)
    if token and token ~= "token-helper-managed" then
      env["VAULT_TOKEN"] = token
    end
    -- vim.notify("[sops.nvim] Using Vault address: " .. addr, vim.log.levels.DEBUG)
  end

  -- Build SOPS command with extracted keys using command line flags
  local sops_args = { "sops", "-e" }

  -- Add KMS keys
  if #keys.kms > 0 then
    table.insert(sops_args, "--kms")
    table.insert(sops_args, table.concat(keys.kms, ","))
  end

  -- Add PGP keys
  if #keys.pgp > 0 then
    table.insert(sops_args, "--pgp")
    table.insert(sops_args, table.concat(keys.pgp, ","))
  end

  -- Add Age keys
  if #keys.age > 0 then
    table.insert(sops_args, "--age")
    table.insert(sops_args, table.concat(keys.age, ","))
  end

  -- Add GCP KMS keys
  if #keys.gcp_kms > 0 then
    table.insert(sops_args, "--gcp-kms")
    table.insert(sops_args, table.concat(keys.gcp_kms, ","))
  end

  -- Add Azure Key Vault keys
  if #keys.azure_kv > 0 then
    table.insert(sops_args, "--azure-kv")
    table.insert(sops_args, table.concat(keys.azure_kv, ","))
  end

  -- Add HashiCorp Vault Transit keys
  if #keys.hc_vault_transit_uri > 0 then
    for _, uri in ipairs(keys.hc_vault_transit_uri) do
      table.insert(sops_args, "--hc-vault-transit")
      table.insert(sops_args, uri)
    end
  end

  -- Detect file format based on extension and add input-type for proper parsing
  local file_ext = path:match("%.([^%.]+)$")
  if file_ext then
    file_ext = file_ext:lower()
    if file_ext == "yaml" or file_ext == "yml" then
      table.insert(sops_args, "--input-type=yaml")
      table.insert(sops_args, "--output-type=yaml")
    elseif file_ext == "json" then
      table.insert(sops_args, "--input-type=json")
      table.insert(sops_args, "--output-type=json")
    elseif file_ext == "env" or file_ext == "dotenv" then
      table.insert(sops_args, "--input-type=dotenv")
      table.insert(sops_args, "--output-type=dotenv")
    elseif file_ext == "ini" then
      table.insert(sops_args, "--input-type=ini")
      table.insert(sops_args, "--output-type=ini")
      -- For other formats, let SOPS auto-detect
    end
  end

  table.insert(sops_args, tmpfile)

  -- vim.notify("[sops.nvim] SOPS command: " .. table.concat(sops_args, " "), vim.log.levels.DEBUG)

  -- Encrypt using SOPS with command line flags
  local result = vim.system(sops_args, { env = env }):wait()

  -- Clean up temporary file
  os.remove(tmpfile)

  if result.code ~= 0 then
    local error_msg = result.stderr or "Unknown error"
    vim.notify("[sops.nvim] Encryption failed: " .. error_msg, vim.log.levels.ERROR)
    return
  end

  -- Get encrypted content from stdout
  local enc_content = result.stdout or ""

  if enc_content == "" then
    vim.notify("[sops.nvim] Encryption produced empty output", vim.log.levels.ERROR)
    return
  end

  -- Write encrypted content back to original file
  local file = io.open(path, "w")
  if not file then
    vim.notify("[sops.nvim] Failed to write encrypted file: " .. path, vim.log.levels.ERROR)
    return
  end

  file:write(enc_content)
  file:close()

  vim.notify("[sops.nvim] Successfully encrypted and saved", vim.log.levels.INFO)
end

return M
