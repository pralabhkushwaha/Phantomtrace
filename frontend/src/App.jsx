import { useState } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Header from './components/Header'
import Dashboard from './pages/Dashboard'
import EmailForensics from './pages/EmailForensics'
import HomographDetection from './pages/HomographDetection'
import URLIntelligence from './pages/URLIntelligence'
import FraudDetection from './pages/FraudDetection'
import MalwareDetection from './pages/MalwareDetection'
import PhoneUPIOSINT from './pages/PhoneUPIOSINT'
import CaseManagement from './pages/CaseManagement'
import RiskAssessment from './pages/RiskAssessment'
import History from './pages/History'
import IndianScamScanner from './pages/IndianScamScanner'
import IPIntelligence from './pages/IPIntelligence'
import SocialOSINT from './pages/SocialOSINT'

export default function App() {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  return (
    <BrowserRouter>
      <div className="flex h-screen overflow-hidden bg-dark-950">
        <Sidebar open={sidebarOpen} setOpen={setSidebarOpen} />
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
          <Header setSidebarOpen={setSidebarOpen} />
          <main className="flex-1 overflow-y-auto p-4 md:p-6">
            <Routes>
              <Route path="/"              element={<Dashboard />} />
              <Route path="/email"         element={<EmailForensics />} />
              <Route path="/homograph"     element={<HomographDetection />} />
              <Route path="/url"           element={<URLIntelligence />} />
              <Route path="/fraud"         element={<FraudDetection />} />
              <Route path="/malware"       element={<MalwareDetection />} />
              <Route path="/phone"         element={<PhoneUPIOSINT />} />
              <Route path="/cases"         element={<CaseManagement />} />
              <Route path="/risk"          element={<RiskAssessment />} />
              <Route path="/history"       element={<History />} />
              <Route path="/indian-scams"  element={<IndianScamScanner />} />
              <Route path="/ip-intel"      element={<IPIntelligence />} />
              <Route path="/social-osint"  element={<SocialOSINT />} />
            </Routes>
          </main>
        </div>
      </div>
    </BrowserRouter>
  )
}
