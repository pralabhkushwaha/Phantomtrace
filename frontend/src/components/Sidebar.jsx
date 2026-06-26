import { NavLink } from 'react-router-dom'
import { clsx } from 'clsx'
import {
  LayoutDashboard, Mail, Globe2, Link2, FileSearch,
  ShieldCheck, Activity, Cpu, ChevronRight, Bug, Phone, Folder,
  Flag, Globe, Users,
} from 'lucide-react'

const NAV_GROUPS = [
  {
    label: 'Investigation Modules',
    items: [
      { to: '/',          icon: LayoutDashboard, label: 'Dashboard' },
      { to: '/email',     icon: Mail,            label: 'Email Forensics' },
      { to: '/homograph', icon: Globe2,          label: 'Homograph Detector' },
      { to: '/url',       icon: Link2,           label: 'URL Intelligence' },
      { to: '/fraud',     icon: FileSearch,      label: 'Fraud Detection' },
      { to: '/malware',   icon: Bug,             label: 'Malware Detection' },
    ],
  },
  {
    label: 'India OSINT',
    items: [
      { to: '/phone',        icon: Phone,  label: 'Phone & UPI OSINT',    badge: 'NEW' },
      { to: '/indian-scams', icon: Flag,   label: 'Indian Scam Scanner',  badge: 'NEW' },
      { to: '/ip-intel',     icon: Globe,  label: 'IP Intelligence',       badge: 'NEW' },
      { to: '/social-osint', icon: Users,  label: 'Social Media OSINT',    badge: 'NEW' },
    ],
  },
  {
    label: 'Case Management',
    items: [
      { to: '/cases',   icon: Folder,      label: 'Cases & FIR Tracking', badge: 'NEW' },
      { to: '/risk',    icon: ShieldCheck, label: 'Risk Assessment' },
      { to: '/history', icon: Activity,    label: 'History' },
    ],
  },
]

export default function Sidebar({ open, setOpen }) {
  return (
    <>
      {open && (
        <div className="fixed inset-0 bg-black/60 z-30 lg:hidden" onClick={() => setOpen(false)} />
      )}
      <aside className={clsx(
        'fixed top-0 left-0 h-full w-64 bg-dark-900 border-r border-dark-700 z-40',
        'flex flex-col transition-transform duration-300',
        open ? 'translate-x-0' : '-translate-x-full',
        'lg:translate-x-0 lg:static lg:z-auto',
      )}>
        {/* Logo */}
        <div className="flex items-center gap-3 px-5 py-4 border-b border-dark-700">
          <div className="w-8 h-8 rounded-lg bg-cyber-700 flex items-center justify-center">
            <Cpu className="w-5 h-5 text-cyber-300" />
          </div>
          <div>
            <div className="text-sm font-bold text-white tracking-wider font-mono">PHANTOM</div>
            <div className="text-xs text-cyber-400 font-mono tracking-widest">TRACE v2</div>
          </div>
        </div>

        {/* Nav Groups */}
        <nav className="flex-1 overflow-y-auto py-3 space-y-4">
          {NAV_GROUPS.map(group => (
            <div key={group.label} className="px-3">
              <p className="px-3 mb-1.5 text-[10px] font-bold uppercase tracking-widest text-dark-400">
                {group.label}
              </p>
              <div className="space-y-0.5">
                {group.items.map(({ to, icon: Icon, label, badge }) => (
                  <NavLink key={to} to={to} end={to === '/'} onClick={() => setOpen(false)}
                    className={({ isActive }) => clsx(
                      'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all group',
                      isActive
                        ? 'bg-cyber-900/50 text-cyber-300 border border-cyber-800'
                        : 'text-gray-400 hover:bg-dark-800 hover:text-gray-200 border border-transparent',
                    )}
                  >
                    {({ isActive }) => (
                      <>
                        <Icon className={clsx('w-4 h-4 shrink-0',
                          isActive ? 'text-cyber-400' : 'text-gray-500 group-hover:text-gray-400'
                        )} />
                        <span className="flex-1">{label}</span>
                        {badge && !isActive && (
                          <span className="text-[9px] px-1.5 py-0.5 rounded font-bold border bg-cyber-900/50 text-cyber-400 border-cyber-800">
                            {badge}
                          </span>
                        )}
                        {isActive && <ChevronRight className="w-3 h-3 shrink-0 text-cyber-500" />}
                      </>
                    )}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-dark-700">
          <p className="text-[10px] text-dark-400 font-mono">PhantomTrace v2.0 · UP Police OSINT</p>
        </div>
      </aside>
    </>
  )
}
