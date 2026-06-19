import { Menu, Bell, Shield } from 'lucide-react'

export default function Header({ setSidebarOpen }) {
  return (
    <header className="h-14 bg-dark-900/80 backdrop-blur border-b border-dark-700 flex items-center px-4 gap-4 sticky top-0 z-20">
      {/* Mobile menu button */}
      <button
        className="lg:hidden p-2 rounded-lg hover:bg-dark-800 text-gray-400 hover:text-gray-200 transition-colors"
        onClick={() => setSidebarOpen(o => !o)}
      >
        <Menu className="w-5 h-5" />
      </button>

      {/* Page context */}
      <div className="flex items-center gap-2 flex-1">
        <Shield className="w-4 h-4 text-cyber-500" />
        <span className="text-xs font-mono text-cyber-400 tracking-wider hidden sm:block">
          THREAT INTELLIGENCE PLATFORM
        </span>
      </div>

      {/* Status indicator */}
      <div className="flex items-center gap-2 text-xs text-green-400">
        <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
        <span className="hidden sm:block font-mono">SYSTEMS ONLINE</span>
      </div>
    </header>
  )
}
