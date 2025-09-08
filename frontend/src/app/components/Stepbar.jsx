"use client";

import { useRouter, usePathname } from 'next/navigation';
import { CheckCircle, Circle, ArrowRight } from 'lucide-react';

export default function Stepbar({ currentStep }) {
  const router = useRouter();
  const pathname = usePathname();

  const steps = [
    {
      id: 'crawl',
      title: 'Crawl',
      path: '/crawl',
      description: 'Discover endpoints'
    },
    {
      id: 'assess', 
      title: 'Assess',
      path: '/assess',
      description: 'Run vulnerability assessment'
    },
    {
      id: 'report',
      title: 'Report', 
      path: '/report',
      description: 'View results and evidence'
    }
  ];

  const getStepStatus = (step) => {
    const currentIndex = steps.findIndex(s => s.id === currentStep);
    const stepIndex = steps.findIndex(s => s.id === step.id);
    
    if (stepIndex < currentIndex) return 'completed';
    if (stepIndex === currentIndex) return 'current';
    return 'upcoming';
  };

  const handleStepClick = (step) => {
    // Only allow navigation to completed steps or current step
    const currentIndex = steps.findIndex(s => s.id === currentStep);
    const stepIndex = steps.findIndex(s => s.id === step.id);
    
    if (stepIndex <= currentIndex) {
      router.push(step.path);
    }
  };

  return (
    <nav className="flex items-center justify-center mb-8">
      <div className="flex items-center space-x-4">
        {steps.map((step, index) => {
          const status = getStepStatus(step);
          const isClickable = status === 'completed' || status === 'current';
          
          return (
            <div key={step.id} className="flex items-center">
              <div
                className={`flex items-center space-x-3 ${
                  isClickable ? 'cursor-pointer' : 'cursor-not-allowed'
                }`}
                onClick={() => isClickable && handleStepClick(step)}
              >
                <div className="flex flex-col items-center">
                  <div
                    className={`w-10 h-10 rounded-full flex items-center justify-center border-2 ${
                      status === 'completed'
                        ? 'bg-green-500 border-green-500 text-white'
                        : status === 'current'
                        ? 'bg-blue-500 border-blue-500 text-white'
                        : 'bg-gray-100 border-gray-300 text-gray-400'
                    }`}
                  >
                    {status === 'completed' ? (
                      <CheckCircle className="w-5 h-5" />
                    ) : (
                      <Circle className="w-5 h-5" />
                    )}
                  </div>
                  <div className="mt-2 text-center">
                    <div
                      className={`text-sm font-medium ${
                        status === 'current'
                          ? 'text-blue-600'
                          : status === 'completed'
                          ? 'text-green-600'
                          : 'text-gray-400'
                      }`}
                    >
                      {step.title}
                    </div>
                    <div
                      className={`text-xs ${
                        status === 'current'
                          ? 'text-blue-500'
                          : status === 'completed'
                          ? 'text-green-500'
                          : 'text-gray-400'
                      }`}
                    >
                      {step.description}
                    </div>
                  </div>
                </div>
              </div>
              
              {index < steps.length - 1 && (
                <ArrowRight className="w-4 h-4 text-gray-400 mx-4" />
              )}
            </div>
          );
        })}
      </div>
    </nav>
  );
}