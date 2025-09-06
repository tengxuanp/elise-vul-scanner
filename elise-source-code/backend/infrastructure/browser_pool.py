"""
AsyncBrowserPool - Reusable Playwright browser instance for web crawling.

This module provides a singleton browser pool that manages a shared Chromium instance
across multiple requests, eliminating the need for asyncio.run() and improving performance.
"""

import asyncio
import logging
from typing import Optional, Dict, Any
from playwright.async_api import async_playwright, Browser, BrowserContext, Playwright

logger = logging.getLogger(__name__)


class AsyncBrowserPool:
    """
    Manages a shared Playwright browser instance for efficient web crawling.
    
    Features:
    - Single browser instance shared across requests
    - Automatic browser installation detection
    - Context isolation with optional storage state
    - Proper cleanup on shutdown
    """
    
    def __init__(self):
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._initialized = False
        self._init_error: Optional[Exception] = None
        self._lock = asyncio.Lock()
    
    async def init(self) -> None:
        """
        Initialize the browser pool with a shared Chromium instance.
        
        Raises:
            RuntimeError: If Chromium is not installed or fails to launch
        """
        async with self._lock:
            if self._initialized:
                return
            
            try:
                logger.info("🚀 Initializing AsyncBrowserPool...")
                self._playwright = await async_playwright().start()
                
                # Launch Chromium with optimized settings for crawling
                self._browser = await self._playwright.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-web-security",
                        "--disable-features=VizDisplayCompositor",
                        "--disable-extensions",
                        "--disable-plugins",
                        "--disable-images",  # Skip images for faster crawling
                        "--disable-javascript",  # We'll enable per context if needed
                    ]
                )
                
                self._initialized = True
                self._init_error = None
                logger.info("✅ AsyncBrowserPool initialized successfully")
                
            except Exception as e:
                error_msg = str(e)
                self._init_error = e
                
                if "Executable doesn't exist" in error_msg or "chromium" in error_msg.lower():
                    helpful_error = RuntimeError(
                        "Run: python -m playwright install --with-deps chromium"
                    )
                    self._init_error = helpful_error
                    raise helpful_error from e
                else:
                    helpful_error = RuntimeError(f"Failed to initialize browser pool: {error_msg}")
                    self._init_error = helpful_error
                    raise helpful_error from e
    
    async def get_context(
        self, 
        storage_state: Optional[str] = None,
        user_agent: Optional[str] = None,
        viewport: Optional[Dict[str, int]] = None,
        enable_js: bool = True
    ) -> BrowserContext:
        """
        Create a new browser context from the shared browser instance.
        
        Args:
            storage_state: Path to storage state file for session persistence
            user_agent: Custom user agent string
            viewport: Viewport dimensions {"width": 1920, "height": 1080}
            enable_js: Whether to enable JavaScript execution
            
        Returns:
            BrowserContext: New isolated browser context
            
        Raises:
            RuntimeError: If browser pool is not initialized
        """
        if not self._initialized:
            raise RuntimeError("Browser pool not initialized. Call init() first.")
        
        context_options = {
            "ignore_https_errors": True,
            "java_script_enabled": enable_js,
        }
        
        if storage_state:
            context_options["storage_state"] = storage_state
        
        if user_agent:
            context_options["user_agent"] = user_agent
        
        if viewport:
            context_options["viewport"] = viewport
        
        context = await self._browser.new_context(**context_options)
        
        # Set reasonable timeouts for crawling
        context.set_default_timeout(30000)  # 30 seconds
        context.set_default_navigation_timeout(30000)
        
        return context
    
    async def shutdown(self) -> None:
        """
        Clean up browser resources and close the pool.
        """
        async with self._lock:
            if not self._initialized:
                return
            
            logger.info("🔄 Shutting down AsyncBrowserPool...")
            
            try:
                if self._browser:
                    await self._browser.close()
                    self._browser = None
                
                if self._playwright:
                    await self._playwright.stop()
                    self._playwright = None
                
                self._initialized = False
                logger.info("✅ AsyncBrowserPool shutdown complete")
                
            except Exception as e:
                logger.error(f"❌ Error during browser pool shutdown: {e}")
    
    @property
    def is_initialized(self) -> bool:
        """Check if the browser pool is initialized and ready."""
        return self._initialized
    
    def is_ready(self) -> bool:
        """Check if the browser pool is ready for use."""
        return self._initialized and self._browser is not None
    
    def get_init_error(self) -> Optional[Exception]:
        """Get the initialization error if any."""
        return self._init_error


# Module-level singleton instance
browser_pool = AsyncBrowserPool()
