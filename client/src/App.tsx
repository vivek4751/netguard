import React from "react";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/NotFound";
import { Route, Switch } from "wouter";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";
import Analysis from "./pages/Analysis";
import Architecture from "./pages/Architecture";
import Home from "./pages/Home";
import Report from "./pages/Report";

function Router() {
  return <Switch><Route path="/" component={Home} /><Route path="/analysis" component={Analysis} /><Route path="/architecture" component={Architecture} /><Route path="/report" component={Report} /><Route path="/404" component={NotFound} /><Route component={NotFound} /></Switch>;
}

export default function App() {
  return <ErrorBoundary><ThemeProvider defaultTheme="dark"><TooltipProvider><Toaster /><Router /></TooltipProvider></ThemeProvider></ErrorBoundary>;
}
