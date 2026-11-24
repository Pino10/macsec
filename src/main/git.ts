/**
 * The git binary to use. While Xcode is the selected developer directory but its licence has not
 * been accepted, /usr/bin/git fails through the xcodebuild shim; the Command Line Tools git still
 * works, so prefer it when it exists.
 */
import { existsSync } from 'fs'

export const gitBin = (): string => (existsSync('/Library/Developer/CommandLineTools/usr/bin/git') ? '/Library/Developer/CommandLineTools/usr/bin/git' : 'git')
