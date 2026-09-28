# Homebrew cask for the Gryphon Agent menu bar app.
#
# A template: it belongs in a tap repository (gocodedotca/homebrew-gryphon, as
# Casks/gryphon-agent.rb), updated for each release with the version and the
# sha256 of the notarized DMG that `task release-client-mac` makes:
#
#   shasum -a 256 "tmp/Gryphon Agent <version>.dmg"
#
# The DMG is attached to the GitHub release of the same tag by hand, and
# GitHub serves it with dots where the file name had spaces, which is what the
# url below is built from. The whole release sequence is docs/RELEASING.md.
#
# The tap repository does not exist yet, so the sha256 below is still a
# placeholder. Installed with:
#   brew install --cask gocodedotca/gryphon/gryphon-agent
cask "gryphon-agent" do
  version "1.0.9"
  sha256 "REPLACE_WITH_THE_DMG_SHA256"

  url "https://github.com/gocodedotca/gryphon-agent/releases/download/v#{version}/Gryphon.Agent.#{version}.dmg"
  name "Gryphon Agent"
  desc "Menu bar agent that measures this Mac for the Gryphon monitoring server"
  homepage "https://github.com/gocodedotca/gryphon-agent"

  depends_on macos: ">= :monterey"

  app "Gryphon Agent.app"

  uninstall quit:      "com.gryphon.agent",
            launchctl: "com.gryphon.agent"

  zap trash: [
    "~/Library/Application Support/Gryphon Agent",
    "~/Library/LaunchAgents/com.gryphon.agent.plist",
    "~/Library/Logs/Gryphon Agent.log",
  ]
end
