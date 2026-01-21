/**
 * Armata-Rampa 2026 - Light Theme
 */

// Utility Functions
const formatPrice = (price) => {
  return new Intl.NumberFormat('ru-RU').format(price) + ' ₽';
};

// Show notification
const showNotification = (message, type = 'success') => {
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  document.body.appendChild(toast);
  
  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
};

// Load Categories
const loadCategories = async () => {
  const grid = document.getElementById('categories-grid');
  if (!grid) return;

  try {
    const response = await fetch('/api/categories');
    const data = await response.json();

    if (data.success && data.data) {
      const icons = {
        'mobilnye-rampy': 'fa-truck-loading',
        'gidravlicheskie-rampy': 'fa-cogs',
        'estakady': 'fa-road',
        'kontejnernye-rampy': 'fa-box'
      };
      
      const colors = {
        'mobilnye-rampy': 'blue',
        'gidravlicheskie-rampy': 'purple',
        'estakady': 'orange',
        'kontejnernye-rampy': 'green'
      };

      grid.innerHTML = data.data.map(cat => {
        const icon = icons[cat.slug] || 'fa-cubes';
        const color = colors[cat.slug] || 'blue';
        return `
        <a href="/katalog?category=${cat.slug}" 
           class="group p-8 bg-white rounded-2xl shadow-sm hover:shadow-lg transition-all border border-neutral-100 hover:border-${color}-200">
          <div class="w-14 h-14 rounded-xl bg-${color}-100 flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
            <i class="fas ${icon} text-2xl text-${color}-600"></i>
          </div>
          <h3 class="text-lg font-semibold text-neutral-800 mb-2">${cat.name}</h3>
          <p class="text-neutral-500 text-sm mb-4">${cat.description || ''}</p>
          <span class="inline-flex items-center text-${color}-600 font-medium text-sm">
            Смотреть <i class="fas fa-arrow-right ml-2 group-hover:translate-x-1 transition-transform"></i>
          </span>
        </a>
      `}).join('');
    }
  } catch (error) {
    console.error('Error loading categories:', error);
  }
};

// Load Featured Products
const loadFeaturedProducts = async () => {
  const container = document.getElementById('featured-products');
  if (!container) return;

  try {
    const response = await fetch('/api/products?limit=6');
    const data = await response.json();

    if (data.success && data.data) {
      container.innerHTML = data.data.slice(0, 6).map(product => `
        <div class="product-card bg-white rounded-2xl shadow-sm overflow-hidden">
          ${product.is_hit ? '<div class="absolute top-4 left-4 z-10"><span class="badge badge-hit"><i class="fas fa-fire mr-1"></i>Хит</span></div>' : ''}
          
          <div class="relative aspect-[4/3] overflow-hidden bg-neutral-100">
            <img src="${product.main_image || 'https://images.unsplash.com/photo-1586528116311-ad8dd3c8310d?w=600&h=400&fit=crop'}" 
                 alt="${product.name}"
                 class="w-full h-full object-cover"
                 loading="lazy">
          </div>
          
          <div class="p-6">
            <div class="flex items-center gap-2 mb-3">
              <span class="text-xs font-medium text-primary-600 bg-primary-50 px-2 py-1 rounded-lg">
                ${product.category_name || 'Рампы'}
              </span>
              ${product.in_stock ? '<span class="badge badge-stock text-xs">В наличии</span>' : ''}
            </div>
            
            <h3 class="text-lg font-semibold text-neutral-800 mb-2 hover:text-primary-600 transition-colors">
              <a href="/product/${product.slug}">${product.name}</a>
            </h3>
            
            <p class="text-neutral-500 text-sm mb-4 line-clamp-2">${product.short_description || ''}</p>
            
            <div class="flex items-center justify-between pt-4 border-t border-neutral-100">
              <div>
                <span class="price">${formatPrice(product.price)}</span>
                <span class="block text-xs text-neutral-400">с НДС</span>
              </div>
              <a href="/product/${product.slug}" 
                 class="px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white text-sm font-medium rounded-xl transition-colors">
                Подробнее
              </a>
            </div>
          </div>
        </div>
      `).join('');
    }
  } catch (error) {
    console.error('Error loading products:', error);
  }
};

// Load Products for Catalog Page
const loadCatalogProducts = async () => {
  const grid = document.getElementById('product-grid');
  const filterContainer = document.getElementById('filter-categories');
  if (!grid) return;

  // Load categories for filter
  if (filterContainer) {
    try {
      const catResponse = await fetch('/api/categories');
      const catData = await catResponse.json();
      
      if (catData.success) {
        filterContainer.innerHTML = `
          <a href="/katalog" class="block px-4 py-2 rounded-lg ${!window.location.search ? 'bg-primary-50 text-primary-600 font-medium' : 'text-neutral-600 hover:bg-neutral-50'}">
            Все категории
          </a>
          ${catData.data.map(cat => `
            <a href="/katalog?category=${cat.slug}" 
               class="block px-4 py-2 rounded-lg ${window.location.search.includes(cat.slug) ? 'bg-primary-50 text-primary-600 font-medium' : 'text-neutral-600 hover:bg-neutral-50'}">
              ${cat.name}
            </a>
          `).join('')}
        `;
      }
    } catch (e) {
      console.error('Error loading categories:', e);
    }
  }

  // Load products
  try {
    const params = new URLSearchParams(window.location.search);
    const category = params.get('category');
    
    const url = category ? `/api/products?category=${category}` : '/api/products';
    const response = await fetch(url);
    const data = await response.json();

    if (data.success && data.data.length > 0) {
      grid.innerHTML = data.data.map(product => `
        <div class="product-card bg-white rounded-2xl shadow-sm overflow-hidden">
          <div class="relative aspect-[4/3] overflow-hidden bg-neutral-100">
            ${product.is_hit ? '<div class="absolute top-3 left-3 z-10"><span class="badge badge-hit text-xs"><i class="fas fa-fire mr-1"></i>Хит</span></div>' : ''}
            <img src="${product.main_image || 'https://images.unsplash.com/photo-1586528116311-ad8dd3c8310d?w=600&h=400&fit=crop'}" 
                 alt="${product.name}"
                 class="w-full h-full object-cover"
                 loading="lazy">
          </div>
          
          <div class="p-5">
            <span class="text-xs font-medium text-primary-600 bg-primary-50 px-2 py-1 rounded-lg">
              ${product.category_name || 'Рампы'}
            </span>
            
            <h3 class="text-lg font-semibold text-neutral-800 mt-3 mb-2">
              <a href="/product/${product.slug}" class="hover:text-primary-600 transition-colors">${product.name}</a>
            </h3>
            
            <div class="flex items-center justify-between pt-4 border-t border-neutral-100 mt-4">
              <span class="text-xl font-bold text-primary-700">${formatPrice(product.price)}</span>
              <a href="/product/${product.slug}" class="text-primary-600 hover:text-primary-700 font-medium text-sm">
                Подробнее <i class="fas fa-arrow-right ml-1"></i>
              </a>
            </div>
          </div>
        </div>
      `).join('');
    } else {
      grid.innerHTML = `
        <div class="col-span-full text-center py-12">
          <i class="fas fa-box-open text-6xl text-neutral-300 mb-4"></i>
          <p class="text-neutral-500 text-lg">Товары не найдены</p>
        </div>
      `;
    }
  } catch (error) {
    console.error('Error loading products:', error);
    grid.innerHTML = '<p class="text-center text-red-500 col-span-full py-12">Ошибка загрузки товаров</p>';
  }
};

// Load Product Detail
const loadProductDetail = async () => {
  const container = document.getElementById('product-detail');
  if (!container) return;

  const slug = container.dataset.slug;
  if (!slug) return;

  try {
    const response = await fetch(`/api/products/${slug}`);
    const data = await response.json();

    if (data.success && data.data) {
      const product = data.data;
      let specs = {};
      try {
        specs = JSON.parse(product.specifications || '{}');
      } catch (e) {}

      container.innerHTML = `
        <nav class="text-sm text-neutral-500 mb-6">
          <a href="/" class="hover:text-primary-600">Главная</a>
          <span class="mx-2">/</span>
          <a href="/katalog" class="hover:text-primary-600">Каталог</a>
          <span class="mx-2">/</span>
          <span class="text-neutral-800">${product.name}</span>
        </nav>
        
        <div class="grid lg:grid-cols-2 gap-12">
          <div>
            <div class="aspect-[4/3] rounded-2xl overflow-hidden bg-neutral-100 mb-4">
              <img src="${product.main_image || 'https://images.unsplash.com/photo-1586528116311-ad8dd3c8310d?w=800&h=600&fit=crop'}" 
                   alt="${product.name}"
                   class="w-full h-full object-cover">
            </div>
          </div>
          
          <div>
            <div class="flex items-center gap-3 mb-4">
              <span class="text-sm font-medium text-primary-600 bg-primary-50 px-3 py-1 rounded-lg">${product.category_name || 'Рампы'}</span>
              ${product.is_hit ? '<span class="badge badge-hit"><i class="fas fa-fire mr-1"></i>Хит продаж</span>' : ''}
              ${product.in_stock ? '<span class="badge badge-stock">В наличии</span>' : ''}
            </div>
            
            <h1 class="text-3xl font-bold text-neutral-800 mb-4">${product.name}</h1>
            
            <p class="text-neutral-600 mb-6">${product.short_description || ''}</p>
            
            <div class="p-6 bg-neutral-50 rounded-2xl mb-6">
              <div class="flex items-baseline gap-2 mb-2">
                <span class="text-4xl font-bold text-primary-700">${formatPrice(product.price)}</span>
              </div>
              <p class="text-neutral-500 text-sm">Цена с НДС 20%</p>
            </div>
            
            <div class="space-y-4 mb-8">
              <a href="#contact-form" class="flex items-center justify-center gap-2 w-full py-4 bg-accent-500 hover:bg-accent-600 text-white font-semibold rounded-xl transition-colors">
                <i class="fas fa-paper-plane"></i>
                Оставить заявку
              </a>
              <a href="tel:+74955553535" class="flex items-center justify-center gap-2 w-full py-4 border-2 border-primary-600 text-primary-600 hover:bg-primary-50 font-semibold rounded-xl transition-colors">
                <i class="fas fa-phone"></i>
                Позвонить
              </a>
            </div>
            
            ${Object.keys(specs).length > 0 ? `
              <div class="border-t border-neutral-200 pt-6">
                <h3 class="text-lg font-semibold text-neutral-800 mb-4">Характеристики</h3>
                <dl class="space-y-3">
                  ${Object.entries(specs).map(([key, value]) => `
                    <div class="flex justify-between py-2 border-b border-neutral-100">
                      <dt class="text-neutral-500">${key}</dt>
                      <dd class="font-medium text-neutral-800">${value}</dd>
                    </div>
                  `).join('')}
                </dl>
              </div>
            ` : ''}
          </div>
        </div>
      `;
    } else {
      container.innerHTML = `
        <div class="text-center py-12">
          <i class="fas fa-exclamation-triangle text-6xl text-neutral-300 mb-4"></i>
          <p class="text-neutral-500 text-lg">Товар не найден</p>
          <a href="/katalog" class="inline-block mt-4 text-primary-600 hover:text-primary-700 font-medium">
            <i class="fas fa-arrow-left mr-2"></i>Вернуться в каталог
          </a>
        </div>
      `;
    }
  } catch (error) {
    console.error('Error loading product:', error);
    container.innerHTML = '<p class="text-center text-red-500 py-12">Ошибка загрузки товара</p>';
  }
};

// Contact Form Handler
const initContactForm = () => {
  const form = document.getElementById('contactForm');
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const submitBtn = form.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Отправка...';
    submitBtn.disabled = true;

    const formData = new FormData(form);
    const data = Object.fromEntries(formData);

    // Add UTM parameters
    const urlParams = new URLSearchParams(window.location.search);
    data.utm_source = urlParams.get('utm_source') || '';
    data.utm_medium = urlParams.get('utm_medium') || '';
    data.utm_campaign = urlParams.get('utm_campaign') || '';

    try {
      const response = await fetch('/api/leads', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });

      const result = await response.json();

      if (result.success) {
        showNotification('Заявка отправлена! Мы скоро свяжемся с вами.', 'success');
        form.reset();
      } else {
        showNotification('Ошибка отправки. Попробуйте еще раз.', 'error');
      }
    } catch (error) {
      showNotification('Ошибка сети. Проверьте подключение.', 'error');
    } finally {
      submitBtn.innerHTML = originalText;
      submitBtn.disabled = false;
    }
  });
};

// Header Scroll Effect
const initHeaderScroll = () => {
  const header = document.querySelector('header');
  if (!header) return;

  window.addEventListener('scroll', () => {
    if (window.scrollY > 50) {
      header.classList.add('scrolled');
    } else {
      header.classList.remove('scrolled');
    }
  });
};

// Mobile Menu
const initMobileMenu = () => {
  const btn = document.getElementById('mobileMenuBtn');
  const menu = document.getElementById('mobileMenu');
  if (!btn || !menu) return;

  btn.addEventListener('click', () => {
    menu.classList.toggle('hidden');
  });
};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  loadCategories();
  loadFeaturedProducts();
  loadCatalogProducts();
  loadProductDetail();
  initContactForm();
  initHeaderScroll();
  initMobileMenu();
  
  console.log('Armata-Rampa loaded');
});
