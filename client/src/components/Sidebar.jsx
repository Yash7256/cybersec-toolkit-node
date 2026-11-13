import { NavLink } from 'react-router-dom';
import {
  Crosshair, MapPin, Contact, Search, ScanLine, Wifi,
  Route, FileText, Shield, Globe2, Fingerprint, LayoutDashboard
} from 'lucide-react';

const navItems = [
  { id: 'dashboard', name: 'Dashboard',   icon: LayoutDashboard, path: '/dashboard' },
];

const tools = [
  { id: 'unified',    name: 'Unified Scan',    icon: Crosshair,      path: '/tools/unified' },
  { id: 'geo',        name: 'Geo IP',          icon: MapPin,         path: '/tools/geo' },
  { id: 'whois',      name: 'WHOIS',           icon: Contact,        path: '/tools/whois' },
  { id: 'subdomains', name: 'Subdomains',      icon: Search,         path: '/tools/subdomains' },
  { id: 'portscanner',name: 'Port Scanner',    icon: ScanLine,       path: '/tools/portscanner' },
  { id: 'osfingerprint', name: 'OS Fingerprinting', icon: Fingerprint, path: '/tools/osfingerprint' },
  { id: 'ping',       name: 'Ping',            icon: Wifi,           path: '/tools/ping' },
  { id: 'traceroute', name: 'Traceroute',      icon: Route,          path: '/tools/traceroute' },
  { id: 'headers',    name: 'HTTP Headers',    icon: FileText,       path: '/tools/headers' },
  { id: 'ssl',        name: 'SSL Check',       icon: Shield,         path: '/tools/ssl' },
  { id: 'webscan',    name: 'Web App Scanner', icon: Globe2,         path: '/tools/webscan' },
];

export default function Sidebar() {
  return (
    <aside
      className="sidebar-panel flex flex-col gap-2 overflow-y-auto"
    >
      {navItems.map(({ id, name, icon: Icon, path }) => (
        <NavLink
          key={id}
          to={path}
          className={({ isActive }) =>
            `nav-item${isActive ? ' active' : ''}`
          }
        >
          <Icon className="w-4 h-4 shrink-0" />
          <span>{name}</span>
        </NavLink>
      ))}
      <div className="my-1 mx-3 border-t" style={{ borderColor: 'rgba(199,183,232,0.1)' }} />
      {tools.map(({ id, name, icon: Icon, path }) => (
        <NavLink
          key={id}
          to={path}
          className={({ isActive }) =>
            `nav-item${isActive ? ' active' : ''}`
          }
        >
          <Icon className="w-4 h-4 shrink-0" />
          <span>{name}</span>
        </NavLink>
      ))}
    </aside>
  );
}
