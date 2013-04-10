$:.unshift(File.join(File.dirname(__FILE__), 'lib'))

require 'pass/version'

spec = Gem::Specification.new do |s|
  s.name = 'pass-ruby'
  s.version = Pass::VERSION
  s.summary = 'Ruby bindings for the Pass API'
  s.description = 'Pass is the easiest way to login online.'
  s.authors = ['James Brennan']
  s.email = ['james@jamesbrennan.ca']
  s.homepage = 'https://passauth.net'
  s.executables = 'pass-console'
  s.require_paths = %w{lib}

  s.add_dependency('rest-client', '~> 1.4')
  s.add_dependency('multi_json', '>= 1.0.4', '< 2')

  s.files = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- test/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ['lib']
end