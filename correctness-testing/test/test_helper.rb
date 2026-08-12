# frozen_string_literal: true

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))

require "dmc_check"

# A missing binary is the most likely first-run failure, and the default error
# ("No such file or directory") does not say what to do about it. Fail here,
# once, with instructions.
begin
  DmcCheck::Cli.assert_available!
rescue DmcCheck::Cli::TransportError => e
  warn e.message
  exit 1
end

# Report which tiers are active, so a passing run in CI shows what it covered.
# A suite that silently skipped its slow half looks identical to one that ran
# everything.
Minitest.after_run do
  unless DmcCheck::Tiers.slow?
    warn "\nslow tiers skipped; set DMC_SLOW_TESTS=1 to include sizes up to " \
         "#{DmcCheck::Tiers::MEDIUM} keys and #{DmcCheck::Tiers::STATISTICAL_PROBES_SLOW} probes"
  end
end
