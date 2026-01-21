import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { serveStatic } from 'hono/cloudflare-pages'

// Types
type Bindings = {
  DB: D1Database
  JWT_SECRET: string
  RESEND_API_KEY: string
  ADMIN_EMAIL: string
}

type Variables = {
  settings: Record<string, string>
  admin: { id: number; username: string } | null
}

// Simple JWT implementation for Cloudflare Workers
const base64UrlEncode = (data: string): string => {
  return btoa(data).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const base64UrlDecode = (data: string): string => {
  const padded = data + '==='.slice(0, (4 - data.length % 4) % 4)
  return atob(padded.replace(/-/g, '+').replace(/_/g, '/'))
}

const createJWT = async (payload: any, secret: string): Promise<string> => {
  const header = { alg: 'HS256', typ: 'JWT' }
  const headerStr = base64UrlEncode(JSON.stringify(header))
  const payloadStr = base64UrlEncode(JSON.stringify({ ...payload, exp: Date.now() + 24 * 60 * 60 * 1000 }))
  const data = `${headerStr}.${payloadStr}`
  
  const encoder = new TextEncoder()
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  )
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data))
  const signatureStr = base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)))
  
  return `${data}.${signatureStr}`
}

const verifyJWT = async (token: string, secret: string): Promise<any | null> => {
  try {
    const [headerStr, payloadStr, signatureStr] = token.split('.')
    if (!headerStr || !payloadStr || !signatureStr) return null
    
    const data = `${headerStr}.${payloadStr}`
    const encoder = new TextEncoder()
    const key = await crypto.subtle.importKey(
      'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    )
    
    const signatureBytes = Uint8Array.from(base64UrlDecode(signatureStr), c => c.charCodeAt(0))
    const valid = await crypto.subtle.verify('HMAC', key, signatureBytes, encoder.encode(data))
    
    if (!valid) return null
    
    const payload = JSON.parse(base64UrlDecode(payloadStr))
    if (payload.exp && payload.exp < Date.now()) return null
    
    return payload
  } catch {
    return null
  }
}

// Hash password with SHA-256
const hashPassword = async (password: string): Promise<string> => {
  const encoder = new TextEncoder()
  const data = encoder.encode(password)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('')
}

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Middleware
app.use('/api/*', cors())

// Load settings middleware
app.use('*', async (c, next) => {
  try {
    const result = await c.env.DB.prepare('SELECT key, value FROM settings').all()
    const settings: Record<string, string> = {}
    result.results?.forEach((row: any) => {
      settings[row.key] = row.value
    })
    c.set('settings', settings)
  } catch (e) {
    c.set('settings', {})
  }
  await next()
})

// ==========================================
// API ROUTES
// ==========================================

// Get all categories
app.get('/api/categories', async (c) => {
  try {
    const result = await c.env.DB.prepare(
      'SELECT * FROM categories WHERE is_active = 1 ORDER BY sort_order'
    ).all()
    return c.json({ success: true, data: result.results })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to fetch categories' }, 500)
  }
})

// Get products
app.get('/api/products', async (c) => {
  try {
    const categorySlug = c.req.query('category')
    let query = `
      SELECT p.*, c.name as category_name, c.slug as category_slug 
      FROM products p 
      LEFT JOIN categories c ON p.category_id = c.id 
      WHERE p.is_active = 1
    `
    if (categorySlug) {
      query += ` AND c.slug = '${categorySlug}'`
    }
    query += ' ORDER BY p.sort_order'
    
    const result = await c.env.DB.prepare(query).all()
    return c.json({ success: true, data: result.results })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to fetch products' }, 500)
  }
})

// Get single product
app.get('/api/products/:slug', async (c) => {
  try {
    const slug = c.req.param('slug')
    const result = await c.env.DB.prepare(`
      SELECT p.*, c.name as category_name, c.slug as category_slug 
      FROM products p 
      LEFT JOIN categories c ON p.category_id = c.id 
      WHERE p.slug = ? AND p.is_active = 1
    `).bind(slug).first()
    
    if (!result) {
      return c.json({ success: false, error: 'Product not found' }, 404)
    }
    
    await c.env.DB.prepare('UPDATE products SET views_count = views_count + 1 WHERE slug = ?').bind(slug).run()
    
    return c.json({ success: true, data: result })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to fetch product' }, 500)
  }
})

// Get reviews
app.get('/api/reviews', async (c) => {
  try {
    const result = await c.env.DB.prepare(
      'SELECT * FROM reviews WHERE is_active = 1 AND is_approved = 1 ORDER BY created_at DESC'
    ).all()
    return c.json({ success: true, data: result.results })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to fetch reviews' }, 500)
  }
})

// Get FAQ
app.get('/api/faq', async (c) => {
  try {
    const result = await c.env.DB.prepare(
      'SELECT * FROM faq WHERE is_active = 1 ORDER BY sort_order'
    ).all()
    return c.json({ success: true, data: result.results })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to fetch FAQ' }, 500)
  }
})

// Get portfolio
app.get('/api/portfolio', async (c) => {
  try {
    const result = await c.env.DB.prepare(
      'SELECT * FROM portfolio WHERE is_active = 1 ORDER BY sort_order'
    ).all()
    return c.json({ success: true, data: result.results })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to fetch portfolio' }, 500)
  }
})

// Get page by slug
app.get('/api/pages/:slug', async (c) => {
  try {
    const slug = c.req.param('slug')
    const result = await c.env.DB.prepare(
      'SELECT * FROM pages WHERE slug = ? AND is_active = 1'
    ).bind(slug).first()
    
    if (!result) {
      return c.json({ success: false, error: 'Page not found' }, 404)
    }
    return c.json({ success: true, data: result })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to fetch page' }, 500)
  }
})

// Get settings
app.get('/api/settings', async (c) => {
  try {
    const result = await c.env.DB.prepare('SELECT key, value FROM settings').all()
    const settings: Record<string, string> = {}
    result.results?.forEach((row: any) => {
      settings[row.key] = row.value
    })
    return c.json({ success: true, data: settings })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to fetch settings' }, 500)
  }
})

// Send email notification via Resend API
const sendEmailNotification = async (env: Bindings, lead: any) => {
  if (!env.RESEND_API_KEY || !env.ADMIN_EMAIL) return
  
  try {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: 'Armata-Rampa <noreply@armata-rampa.ru>',
        to: [env.ADMIN_EMAIL],
        subject: `Новая заявка от ${lead.name}`,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #1e40af;">Новая заявка с сайта Armata-Rampa</h2>
            <table style="width: 100%; border-collapse: collapse;">
              <tr><td style="padding: 10px; border-bottom: 1px solid #e5e7eb;"><strong>Имя:</strong></td><td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">${lead.name}</td></tr>
              <tr><td style="padding: 10px; border-bottom: 1px solid #e5e7eb;"><strong>Телефон:</strong></td><td style="padding: 10px; border-bottom: 1px solid #e5e7eb;"><a href="tel:${lead.phone}">${lead.phone}</a></td></tr>
              ${lead.email ? `<tr><td style="padding: 10px; border-bottom: 1px solid #e5e7eb;"><strong>Email:</strong></td><td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">${lead.email}</td></tr>` : ''}
              ${lead.company ? `<tr><td style="padding: 10px; border-bottom: 1px solid #e5e7eb;"><strong>Компания:</strong></td><td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">${lead.company}</td></tr>` : ''}
              ${lead.message ? `<tr><td style="padding: 10px; border-bottom: 1px solid #e5e7eb;"><strong>Сообщение:</strong></td><td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">${lead.message}</td></tr>` : ''}
            </table>
          </div>
        `
      })
    })
  } catch (e) {
    console.error('Failed to send email:', e)
  }
}

// Submit lead/request
app.post('/api/leads', async (c) => {
  try {
    const body = await c.req.json()
    const { name, phone, email, company, message, product_id, source } = body
    
    if (!name || !phone) {
      return c.json({ success: false, error: 'Name and phone are required' }, 400)
    }
    
    const utm_source = body.utm_source || ''
    const utm_medium = body.utm_medium || ''
    const utm_campaign = body.utm_campaign || ''
    
    await c.env.DB.prepare(`
      INSERT INTO leads (name, phone, email, company, message, product_id, source, utm_source, utm_medium, utm_campaign)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(name, phone, email || '', company || '', message || '', product_id || null, source || 'website', utm_source, utm_medium, utm_campaign).run()
    
    sendEmailNotification(c.env, { name, phone, email, company, message, source })
    
    return c.json({ success: true, message: 'Request submitted successfully' })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to submit request' }, 500)
  }
})

// ==========================================
// ADMIN AUTHENTICATION ROUTES
// ==========================================

app.post('/api/admin/login', async (c) => {
  try {
    const { username, password } = await c.req.json()
    
    if (!username || !password) {
      return c.json({ success: false, error: 'Введите логин и пароль' }, 400)
    }
    
    const passwordHash = await hashPassword(password)
    
    const admin = await c.env.DB.prepare(`
      SELECT id, username, email, role FROM admin_users 
      WHERE username = ? AND password_hash = ? AND is_active = 1
    `).bind(username, passwordHash).first()
    
    if (!admin) {
      return c.json({ success: false, error: 'Неверный логин или пароль' }, 401)
    }
    
    await c.env.DB.prepare(`
      UPDATE admin_users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
    `).bind(admin.id).run()
    
    const secret = c.env.JWT_SECRET || 'default-secret-change-me'
    const token = await createJWT({ id: admin.id, username: admin.username, role: admin.role }, secret)
    
    return c.json({ 
      success: true, 
      token,
      user: { id: admin.id, username: admin.username, email: admin.email, role: admin.role }
    })
  } catch (e: any) {
    return c.json({ success: false, error: 'Ошибка авторизации' }, 500)
  }
})

app.get('/api/admin/verify', async (c) => {
  try {
    const authHeader = c.req.header('Authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return c.json({ success: false, error: 'Unauthorized' }, 401)
    }
    
    const token = authHeader.slice(7)
    const secret = c.env.JWT_SECRET || 'default-secret-change-me'
    const payload = await verifyJWT(token, secret)
    
    if (!payload) {
      return c.json({ success: false, error: 'Invalid token' }, 401)
    }
    
    return c.json({ success: true, user: payload })
  } catch (e) {
    return c.json({ success: false, error: 'Unauthorized' }, 401)
  }
})

app.get('/api/admin/stats', async (c) => {
  try {
    const [products, leads, newLeads, views] = await Promise.all([
      c.env.DB.prepare('SELECT COUNT(*) as count FROM products WHERE is_active = 1').first(),
      c.env.DB.prepare('SELECT COUNT(*) as count FROM leads').first(),
      c.env.DB.prepare("SELECT COUNT(*) as count FROM leads WHERE status = 'new'").first(),
      c.env.DB.prepare('SELECT SUM(views_count) as count FROM products').first()
    ])
    
    return c.json({
      success: true,
      stats: {
        totalProducts: (products as any)?.count || 0,
        totalLeads: (leads as any)?.count || 0,
        newLeads: (newLeads as any)?.count || 0,
        totalViews: (views as any)?.count || 0
      }
    })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to fetch stats' }, 500)
  }
})

// ==========================================
// ADMIN API ROUTES
// ==========================================

app.get('/api/admin/leads', async (c) => {
  try {
    const result = await c.env.DB.prepare(`
      SELECT l.*, p.name as product_name 
      FROM leads l 
      LEFT JOIN products p ON l.product_id = p.id 
      ORDER BY l.created_at DESC
    `).all()
    return c.json({ success: true, data: result.results })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to fetch leads' }, 500)
  }
})

app.put('/api/admin/leads/:id', async (c) => {
  try {
    const id = c.req.param('id')
    const { status, notes } = await c.req.json()
    
    await c.env.DB.prepare(`
      UPDATE leads SET status = ?, notes = ?, processed_at = CURRENT_TIMESTAMP WHERE id = ?
    `).bind(status, notes || '', id).run()
    
    return c.json({ success: true })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to update lead' }, 500)
  }
})

app.get('/api/admin/products', async (c) => {
  try {
    const result = await c.env.DB.prepare(`
      SELECT p.*, c.name as category_name 
      FROM products p 
      LEFT JOIN categories c ON p.category_id = c.id 
      ORDER BY p.sort_order
    `).all()
    return c.json({ success: true, data: result.results })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to fetch products' }, 500)
  }
})

app.post('/api/admin/products', async (c) => {
  try {
    const body = await c.req.json()
    const { 
      category_id, slug, name, short_description, full_description,
      price, old_price, in_stock, is_hit, is_new, is_sale,
      specifications, seo_title, seo_description, seo_keywords,
      images, main_image, sort_order, is_active
    } = body
    
    const result = await c.env.DB.prepare(`
      INSERT INTO products (category_id, slug, name, short_description, full_description, price, old_price, in_stock, is_hit, is_new, is_sale, specifications, seo_title, seo_description, seo_keywords, images, main_image, sort_order, is_active)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      category_id, slug, name, short_description || '', full_description || '',
      price, old_price || null, in_stock ? 1 : 0, is_hit ? 1 : 0, is_new ? 1 : 0, is_sale ? 1 : 0,
      JSON.stringify(specifications || {}), seo_title || '', seo_description || '', seo_keywords || '',
      JSON.stringify(images || []), main_image || '', sort_order || 0, is_active ? 1 : 0
    ).run()
    
    return c.json({ success: true, id: result.meta.last_row_id })
  } catch (e: any) {
    return c.json({ success: false, error: e.message || 'Failed to create product' }, 500)
  }
})

app.put('/api/admin/products/:id', async (c) => {
  try {
    const id = c.req.param('id')
    const body = await c.req.json()
    const { 
      category_id, slug, name, short_description, full_description,
      price, old_price, in_stock, is_hit, is_new, is_sale,
      specifications, seo_title, seo_description, seo_keywords,
      images, main_image, sort_order, is_active
    } = body
    
    await c.env.DB.prepare(`
      UPDATE products SET 
        category_id = ?, slug = ?, name = ?, short_description = ?, full_description = ?,
        price = ?, old_price = ?, in_stock = ?, is_hit = ?, is_new = ?, is_sale = ?,
        specifications = ?, seo_title = ?, seo_description = ?, seo_keywords = ?,
        images = ?, main_image = ?, sort_order = ?, is_active = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).bind(
      category_id, slug, name, short_description || '', full_description || '',
      price, old_price || null, in_stock ? 1 : 0, is_hit ? 1 : 0, is_new ? 1 : 0, is_sale ? 1 : 0,
      JSON.stringify(specifications || {}), seo_title || '', seo_description || '', seo_keywords || '',
      JSON.stringify(images || []), main_image || '', sort_order || 0, is_active ? 1 : 0, id
    ).run()
    
    return c.json({ success: true })
  } catch (e: any) {
    return c.json({ success: false, error: e.message || 'Failed to update product' }, 500)
  }
})

app.delete('/api/admin/products/:id', async (c) => {
  try {
    const id = c.req.param('id')
    await c.env.DB.prepare('DELETE FROM products WHERE id = ?').bind(id).run()
    return c.json({ success: true })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to delete product' }, 500)
  }
})

app.put('/api/admin/settings', async (c) => {
  try {
    const settings = await c.req.json()
    
    for (const [key, value] of Object.entries(settings)) {
      await c.env.DB.prepare(`
        INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
      `).bind(key, value).run()
    }
    
    return c.json({ success: true })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to update settings' }, 500)
  }
})

// ==========================================
// STATIC FILES
// ==========================================

app.use('/static/*', serveStatic())
app.use('/images/*', serveStatic())

// ==========================================
// LIGHT THEME 2026 - CALM COLORS
// ==========================================

const renderPage = (title: string, content: string, seoTitle?: string, seoDescription?: string) => {
  return `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${seoTitle || title} | Armata-Rampa</title>
  <meta name="description" content="${seoDescription || 'Производитель погрузочных рамп и эстакад. Собственное производство, гарантия качества, доставка по России.'}">
  
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      theme: {
        extend: {
          fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'] },
          colors: {
            primary: {
              50: '#eff6ff', 100: '#dbeafe', 200: '#bfdbfe', 300: '#93c5fd',
              400: '#60a5fa', 500: '#3b82f6', 600: '#2563eb', 700: '#1d4ed8',
              800: '#1e40af', 900: '#1e3a8a'
            },
            accent: {
              50: '#fff7ed', 100: '#ffedd5', 200: '#fed7aa', 300: '#fdba74',
              400: '#fb923c', 500: '#f97316', 600: '#ea580c', 700: '#c2410c'
            },
            neutral: {
              50: '#fafafa', 100: '#f5f5f5', 200: '#e5e5e5', 300: '#d4d4d4',
              400: '#a3a3a3', 500: '#737373', 600: '#525252', 700: '#404040',
              800: '#262626', 900: '#171717'
            }
          }
        }
      }
    }
  </script>
  
  <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.5.0/css/all.min.css" rel="stylesheet">
  <link href="/static/styles.css" rel="stylesheet">
  
  <script type="application/ld+json">
  {"@context":"https://schema.org","@type":"Organization","name":"Armata-Rampa","description":"Производитель погрузочных рамп и эстакад","url":"https://armata-rampa.ru"}
  </script>
</head>
<body class="bg-neutral-50 text-neutral-800 font-sans antialiased">
  ${content}
  <script src="https://cdn.jsdelivr.net/npm/axios@1.6.0/dist/axios.min.js"></script>
  <script src="/static/app.js"></script>
</body>
</html>`
}

// Main page
app.get('/', async (c) => {
  const settings = c.get('settings')
  
  const content = `
  <!-- Header -->
  <header class="bg-white shadow-sm sticky top-0 z-50">
    <div class="max-w-7xl mx-auto">
      <div class="hidden lg:flex items-center justify-between px-6 py-2 border-b border-neutral-100 text-sm">
        <div class="flex items-center gap-6 text-neutral-600">
          <span><i class="fas fa-map-marker-alt text-primary-500 mr-2"></i>${settings.address || 'г. Владимир, ул. Промышленная, д. 10'}</span>
          <span><i class="fas fa-clock text-primary-500 mr-2"></i>${settings.working_hours || 'Пн-Пт: 9:00-18:00'}</span>
        </div>
        <div class="flex items-center gap-4">
          <a href="mailto:${settings.email || 'info@armata-rampa.ru'}" class="text-neutral-600 hover:text-primary-600 transition-colors">
            <i class="fas fa-envelope mr-2"></i>${settings.email || 'info@armata-rampa.ru'}
          </a>
        </div>
      </div>
      
      <nav class="flex items-center justify-between px-6 py-4">
        <a href="/" class="flex items-center gap-3">
          <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-primary-500 to-primary-700 flex items-center justify-center shadow-lg shadow-primary-500/20">
            <span class="text-white font-bold text-xl">A</span>
          </div>
          <div>
            <span class="text-xl font-bold text-neutral-800">ARMATA</span>
            <span class="text-xl font-bold text-accent-500">RAMPA</span>
          </div>
        </a>
        
        <div class="hidden lg:flex items-center gap-1">
          <a href="/katalog" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Каталог</a>
          <a href="/o-kompanii" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">О компании</a>
          <a href="/portfolio" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Портфолио</a>
          <a href="/dostavka" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Доставка</a>
          <a href="/kontakty" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Контакты</a>
        </div>
        
        <div class="flex items-center gap-4">
          <a href="tel:${settings.phone_main || '+74955553535'}" class="hidden md:flex items-center gap-3">
            <div class="w-12 h-12 rounded-xl bg-primary-50 flex items-center justify-center">
              <i class="fas fa-phone text-primary-600"></i>
            </div>
            <div>
              <div class="text-xs text-neutral-500">Звоните</div>
              <div class="font-semibold text-neutral-800">${settings.phone_main || '+7 (495) 555-35-35'}</div>
            </div>
          </a>
          <a href="#contact-form" class="hidden sm:inline-flex px-6 py-3 bg-accent-500 hover:bg-accent-600 text-white font-semibold rounded-xl shadow-lg shadow-accent-500/30 transition-all">
            Оставить заявку
          </a>
          <button id="mobileMenuBtn" class="lg:hidden w-12 h-12 rounded-xl bg-neutral-100 flex items-center justify-center">
            <i class="fas fa-bars text-neutral-600"></i>
          </button>
        </div>
      </nav>
    </div>
  </header>

  <!-- Hero Section -->
  <section class="relative bg-gradient-to-br from-primary-600 via-primary-700 to-primary-800 py-20 lg:py-28 overflow-hidden">
    <div class="absolute inset-0 opacity-10">
      <div class="absolute top-20 left-10 w-72 h-72 bg-white rounded-full blur-3xl"></div>
      <div class="absolute bottom-10 right-10 w-96 h-96 bg-accent-500 rounded-full blur-3xl"></div>
    </div>
    
    <div class="relative max-w-7xl mx-auto px-6">
      <div class="max-w-3xl">
        <div class="inline-flex items-center gap-2 px-4 py-2 bg-white/10 backdrop-blur rounded-full text-white/90 text-sm mb-6">
          <i class="fas fa-award"></i>
          <span>Производитель с 2010 года</span>
        </div>
        
        <h1 class="text-4xl lg:text-6xl font-bold text-white mb-6 leading-tight">
          Погрузочные рампы и эстакады
          <span class="text-accent-400">от производителя</span>
        </h1>
        
        <p class="text-xl text-white/80 mb-8 leading-relaxed">
          Собственное производство во Владимире. Гарантия 1 год. 
          Доставка по всей России. Цены от 250 000 ₽.
        </p>
        
        <div class="flex flex-wrap gap-4">
          <a href="/katalog" class="inline-flex items-center gap-2 px-8 py-4 bg-white text-primary-700 font-semibold rounded-xl hover:bg-neutral-100 transition-all shadow-xl">
            <i class="fas fa-th-large"></i>
            Смотреть каталог
          </a>
          <a href="#contact-form" class="inline-flex items-center gap-2 px-8 py-4 bg-accent-500 text-white font-semibold rounded-xl hover:bg-accent-600 transition-all shadow-xl shadow-accent-500/30">
            <i class="fas fa-paper-plane"></i>
            Получить расчет
          </a>
        </div>
        
        <div class="flex flex-wrap gap-8 mt-12 pt-8 border-t border-white/20">
          <div>
            <div class="text-3xl font-bold text-white">500+</div>
            <div class="text-white/70">Проектов</div>
          </div>
          <div>
            <div class="text-3xl font-bold text-white">12 лет</div>
            <div class="text-white/70">На рынке</div>
          </div>
          <div>
            <div class="text-3xl font-bold text-white">1 год</div>
            <div class="text-white/70">Гарантия</div>
          </div>
          <div>
            <div class="text-3xl font-bold text-white">РФ</div>
            <div class="text-white/70">Доставка</div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- Categories -->
  <section class="py-16 lg:py-24">
    <div class="max-w-7xl mx-auto px-6">
      <div class="text-center mb-12">
        <h2 class="text-3xl lg:text-4xl font-bold text-neutral-800 mb-4">Категории продукции</h2>
        <p class="text-neutral-600 max-w-2xl mx-auto">Широкий выбор погрузочного оборудования для складов и логистических центров</p>
      </div>
      
      <div id="categories-grid" class="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
        <!-- Categories loaded via JS -->
      </div>
    </div>
  </section>

  <!-- Featured Products -->
  <section class="py-16 lg:py-24 bg-neutral-100">
    <div class="max-w-7xl mx-auto px-6">
      <div class="flex flex-col md:flex-row md:items-end md:justify-between mb-12">
        <div>
          <h2 class="text-3xl lg:text-4xl font-bold text-neutral-800 mb-4">Популярные товары</h2>
          <p class="text-neutral-600">Хиты продаж и новинки каталога</p>
        </div>
        <a href="/katalog" class="inline-flex items-center gap-2 text-primary-600 font-semibold hover:text-primary-700 mt-4 md:mt-0">
          Весь каталог <i class="fas fa-arrow-right"></i>
        </a>
      </div>
      
      <div id="featured-products" class="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
        <!-- Products loaded via JS -->
      </div>
    </div>
  </section>

  <!-- Advantages -->
  <section class="py-16 lg:py-24">
    <div class="max-w-7xl mx-auto px-6">
      <div class="text-center mb-12">
        <h2 class="text-3xl lg:text-4xl font-bold text-neutral-800 mb-4">Почему выбирают нас</h2>
        <p class="text-neutral-600 max-w-2xl mx-auto">Более 500 успешных проектов по всей России</p>
      </div>
      
      <div class="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div class="p-8 bg-white rounded-2xl shadow-sm hover:shadow-lg transition-shadow">
          <div class="w-14 h-14 rounded-xl bg-primary-100 flex items-center justify-center mb-4">
            <i class="fas fa-industry text-2xl text-primary-600"></i>
          </div>
          <h3 class="text-lg font-semibold text-neutral-800 mb-2">Собственное производство</h3>
          <p class="text-neutral-600 text-sm">Контролируем качество на всех этапах изготовления</p>
        </div>
        
        <div class="p-8 bg-white rounded-2xl shadow-sm hover:shadow-lg transition-shadow">
          <div class="w-14 h-14 rounded-xl bg-accent-100 flex items-center justify-center mb-4">
            <i class="fas fa-certificate text-2xl text-accent-600"></i>
          </div>
          <h3 class="text-lg font-semibold text-neutral-800 mb-2">Сертификация</h3>
          <p class="text-neutral-600 text-sm">Вся продукция соответствует ГОСТ и имеет сертификаты</p>
        </div>
        
        <div class="p-8 bg-white rounded-2xl shadow-sm hover:shadow-lg transition-shadow">
          <div class="w-14 h-14 rounded-xl bg-green-100 flex items-center justify-center mb-4">
            <i class="fas fa-shield-alt text-2xl text-green-600"></i>
          </div>
          <h3 class="text-lg font-semibold text-neutral-800 mb-2">Гарантия 1 год</h3>
          <p class="text-neutral-600 text-sm">Гарантийное обслуживание и поставка запчастей</p>
        </div>
        
        <div class="p-8 bg-white rounded-2xl shadow-sm hover:shadow-lg transition-shadow">
          <div class="w-14 h-14 rounded-xl bg-blue-100 flex items-center justify-center mb-4">
            <i class="fas fa-truck text-2xl text-blue-600"></i>
          </div>
          <h3 class="text-lg font-semibold text-neutral-800 mb-2">Доставка по РФ</h3>
          <p class="text-neutral-600 text-sm">Выгодные условия доставки в любой регион России</p>
        </div>
      </div>
    </div>
  </section>

  <!-- Contact Form -->
  <section id="contact-form" class="py-16 lg:py-24 bg-primary-600">
    <div class="max-w-7xl mx-auto px-6">
      <div class="grid lg:grid-cols-2 gap-12 items-center">
        <div class="text-white">
          <h2 class="text-3xl lg:text-4xl font-bold mb-6">Получите расчет стоимости</h2>
          <p class="text-white/80 text-lg mb-8">Оставьте заявку и наш специалист свяжется с вами в течение 30 минут для консультации и расчета</p>
          
          <div class="space-y-4">
            <div class="flex items-center gap-4">
              <div class="w-12 h-12 rounded-xl bg-white/10 flex items-center justify-center">
                <i class="fas fa-phone text-white"></i>
              </div>
              <div>
                <div class="text-white/60 text-sm">Телефон</div>
                <a href="tel:${settings.phone_main || '+74955553535'}" class="text-white font-semibold">${settings.phone_main || '+7 (495) 555-35-35'}</a>
              </div>
            </div>
            <div class="flex items-center gap-4">
              <div class="w-12 h-12 rounded-xl bg-white/10 flex items-center justify-center">
                <i class="fas fa-envelope text-white"></i>
              </div>
              <div>
                <div class="text-white/60 text-sm">Email</div>
                <a href="mailto:${settings.email || 'info@armata-rampa.ru'}" class="text-white font-semibold">${settings.email || 'info@armata-rampa.ru'}</a>
              </div>
            </div>
          </div>
        </div>
        
        <div class="bg-white rounded-3xl p-8 shadow-2xl">
          <form id="contactForm" class="space-y-5">
            <div>
              <label class="block text-sm font-medium text-neutral-700 mb-2">Ваше имя *</label>
              <input type="text" name="name" required class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-primary-500 focus:ring-2 focus:ring-primary-500/20 transition-all" placeholder="Иван Иванов">
            </div>
            <div>
              <label class="block text-sm font-medium text-neutral-700 mb-2">Телефон *</label>
              <input type="tel" name="phone" required class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-primary-500 focus:ring-2 focus:ring-primary-500/20 transition-all" placeholder="+7 (___) ___-__-__">
            </div>
            <div>
              <label class="block text-sm font-medium text-neutral-700 mb-2">Email</label>
              <input type="email" name="email" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-primary-500 focus:ring-2 focus:ring-primary-500/20 transition-all" placeholder="email@company.ru">
            </div>
            <div>
              <label class="block text-sm font-medium text-neutral-700 mb-2">Сообщение</label>
              <textarea name="message" rows="3" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-primary-500 focus:ring-2 focus:ring-primary-500/20 transition-all resize-none" placeholder="Опишите ваш запрос..."></textarea>
            </div>
            <button type="submit" class="w-full py-4 bg-accent-500 hover:bg-accent-600 text-white font-semibold rounded-xl shadow-lg shadow-accent-500/30 transition-all">
              Отправить заявку
            </button>
            <p class="text-xs text-neutral-500 text-center">Нажимая кнопку, вы соглашаетесь с политикой конфиденциальности</p>
          </form>
        </div>
      </div>
    </div>
  </section>

  <!-- Footer -->
  <footer class="bg-neutral-800 text-white py-12">
    <div class="max-w-7xl mx-auto px-6">
      <div class="grid md:grid-cols-4 gap-8 mb-8">
        <div>
          <div class="flex items-center gap-3 mb-4">
            <div class="w-10 h-10 rounded-lg bg-primary-500 flex items-center justify-center">
              <span class="text-white font-bold">A</span>
            </div>
            <span class="text-lg font-bold">ARMATA<span class="text-accent-400">RAMPA</span></span>
          </div>
          <p class="text-neutral-400 text-sm">Производитель погрузочных рамп и эстакад с 2010 года</p>
        </div>
        
        <div>
          <h4 class="font-semibold mb-4">Каталог</h4>
          <ul class="space-y-2 text-neutral-400 text-sm">
            <li><a href="/katalog/mobilnye-rampy" class="hover:text-white transition-colors">Мобильные рампы</a></li>
            <li><a href="/katalog/gidravlicheskie-rampy" class="hover:text-white transition-colors">Гидравлические рампы</a></li>
            <li><a href="/katalog/estakady" class="hover:text-white transition-colors">Эстакады</a></li>
          </ul>
        </div>
        
        <div>
          <h4 class="font-semibold mb-4">Информация</h4>
          <ul class="space-y-2 text-neutral-400 text-sm">
            <li><a href="/o-kompanii" class="hover:text-white transition-colors">О компании</a></li>
            <li><a href="/dostavka" class="hover:text-white transition-colors">Доставка и оплата</a></li>
            <li><a href="/kontakty" class="hover:text-white transition-colors">Контакты</a></li>
          </ul>
        </div>
        
        <div>
          <h4 class="font-semibold mb-4">Контакты</h4>
          <ul class="space-y-2 text-neutral-400 text-sm">
            <li><i class="fas fa-phone mr-2 text-primary-400"></i>${settings.phone_main || '+7 (495) 555-35-35'}</li>
            <li><i class="fas fa-envelope mr-2 text-primary-400"></i>${settings.email || 'info@armata-rampa.ru'}</li>
            <li><i class="fas fa-map-marker-alt mr-2 text-primary-400"></i>${settings.address || 'г. Владимир'}</li>
          </ul>
        </div>
      </div>
      
      <div class="pt-8 border-t border-neutral-700 text-center text-neutral-500 text-sm">
        &copy; 2024 Armata-Rampa. Все права защищены.
      </div>
    </div>
  </footer>
  `
  
  return c.html(renderPage('Главная', content, 'Armata-Rampa — Погрузочные рампы и эстакады от производителя', 
    'Производитель погрузочных рамп и эстакад. Мобильные рампы от 449 000 ₽, гидравлические рампы от 679 000 ₽. Гарантия 1 год. Доставка по России.'))
})

// Catalog page
app.get('/katalog', async (c) => {
  const content = `
  <header class="bg-white shadow-sm sticky top-0 z-50">
    <div class="max-w-7xl mx-auto">
      <nav class="flex items-center justify-between px-6 py-4">
        <a href="/" class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-lg bg-primary-500 flex items-center justify-center">
            <span class="text-white font-bold">A</span>
          </div>
          <span class="text-lg font-bold text-neutral-800">ARMATA<span class="text-accent-500">RAMPA</span></span>
        </a>
        <div class="hidden lg:flex items-center gap-1">
          <a href="/katalog" class="px-4 py-2 rounded-lg text-primary-600 bg-primary-50 font-medium">Каталог</a>
          <a href="/o-kompanii" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">О компании</a>
          <a href="/dostavka" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Доставка</a>
          <a href="/kontakty" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Контакты</a>
        </div>
        <a href="tel:+74955553535" class="hidden md:flex items-center gap-2 text-primary-600 font-semibold">
          <i class="fas fa-phone"></i> +7 (495) 555-35-35
        </a>
      </nav>
    </div>
  </header>

  <main class="py-12">
    <div class="max-w-7xl mx-auto px-6">
      <div class="mb-8">
        <h1 class="text-3xl font-bold text-neutral-800 mb-2">Каталог продукции</h1>
        <p class="text-neutral-600">Погрузочные рампы и эстакады от производителя</p>
      </div>
      
      <div class="grid lg:grid-cols-4 gap-8">
        <aside class="lg:col-span-1">
          <div class="bg-white rounded-2xl p-6 shadow-sm sticky top-24">
            <h3 class="font-semibold text-neutral-800 mb-4">Категории</h3>
            <div id="filter-categories" class="space-y-2">
              <!-- Categories loaded via JS -->
            </div>
          </div>
        </aside>
        
        <div class="lg:col-span-3">
          <div id="product-grid" class="grid md:grid-cols-2 xl:grid-cols-3 gap-6">
            <!-- Products loaded via JS -->
          </div>
        </div>
      </div>
    </div>
  </main>

  <footer class="bg-neutral-800 text-white py-8 mt-12">
    <div class="max-w-7xl mx-auto px-6 text-center text-neutral-400 text-sm">
      &copy; 2024 Armata-Rampa. Все права защищены.
    </div>
  </footer>
  `
  
  return c.html(renderPage('Каталог продукции', content, 'Каталог рамп и эстакад | Armata-Rampa', 
    'Каталог погрузочных рамп и эстакад от производителя. Мобильные, гидравлические рампы, эстакады. Цены, характеристики.'))
})

// Product page
app.get('/product/:slug', async (c) => {
  const slug = c.req.param('slug')
  
  const content = `
  <header class="bg-white shadow-sm sticky top-0 z-50">
    <div class="max-w-7xl mx-auto">
      <nav class="flex items-center justify-between px-6 py-4">
        <a href="/" class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-lg bg-primary-500 flex items-center justify-center">
            <span class="text-white font-bold">A</span>
          </div>
          <span class="text-lg font-bold text-neutral-800">ARMATA<span class="text-accent-500">RAMPA</span></span>
        </a>
        <div class="hidden lg:flex items-center gap-1">
          <a href="/katalog" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Каталог</a>
          <a href="/kontakty" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Контакты</a>
        </div>
        <a href="tel:+74955553535" class="hidden md:flex items-center gap-2 text-primary-600 font-semibold">
          <i class="fas fa-phone"></i> +7 (495) 555-35-35
        </a>
      </nav>
    </div>
  </header>

  <main class="py-12">
    <div class="max-w-7xl mx-auto px-6">
      <div id="product-detail" data-slug="${slug}">
        <div class="text-center py-12">
          <i class="fas fa-spinner fa-spin text-4xl text-primary-500"></i>
          <p class="mt-4 text-neutral-500">Загрузка...</p>
        </div>
      </div>
    </div>
  </main>

  <footer class="bg-neutral-800 text-white py-8 mt-12">
    <div class="max-w-7xl mx-auto px-6 text-center text-neutral-400 text-sm">
      &copy; 2024 Armata-Rampa. Все права защищены.
    </div>
  </footer>
  `
  
  return c.html(renderPage('Товар', content))
})

// Static pages
app.get('/o-kompanii', async (c) => {
  const content = `
  <header class="bg-white shadow-sm sticky top-0 z-50">
    <div class="max-w-7xl mx-auto">
      <nav class="flex items-center justify-between px-6 py-4">
        <a href="/" class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-lg bg-primary-500 flex items-center justify-center">
            <span class="text-white font-bold">A</span>
          </div>
          <span class="text-lg font-bold text-neutral-800">ARMATA<span class="text-accent-500">RAMPA</span></span>
        </a>
        <div class="hidden lg:flex items-center gap-1">
          <a href="/katalog" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Каталог</a>
          <a href="/o-kompanii" class="px-4 py-2 rounded-lg text-primary-600 bg-primary-50 font-medium">О компании</a>
          <a href="/dostavka" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Доставка</a>
          <a href="/kontakty" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Контакты</a>
        </div>
      </nav>
    </div>
  </header>

  <main class="py-12">
    <div class="max-w-4xl mx-auto px-6">
      <h1 class="text-3xl font-bold text-neutral-800 mb-8">О компании Armata-Rampa</h1>
      
      <div class="prose prose-lg max-w-none">
        <p class="text-neutral-600 text-lg leading-relaxed mb-6">
          Компания Armata-Rampa — один из ведущих российских производителей погрузочного оборудования. 
          С 2010 года мы разрабатываем и изготавливаем погрузочные рампы и эстакады для складов, 
          логистических центров и производственных предприятий.
        </p>
        
        <div class="grid md:grid-cols-2 gap-6 my-8">
          <div class="p-6 bg-primary-50 rounded-2xl">
            <h3 class="font-semibold text-primary-800 mb-2"><i class="fas fa-industry mr-2"></i>Собственное производство</h3>
            <p class="text-primary-700 text-sm">Полный цикл производства на собственных мощностях во Владимире</p>
          </div>
          <div class="p-6 bg-accent-50 rounded-2xl">
            <h3 class="font-semibold text-accent-800 mb-2"><i class="fas fa-certificate mr-2"></i>Сертификация</h3>
            <p class="text-accent-700 text-sm">Вся продукция сертифицирована и соответствует ГОСТ</p>
          </div>
          <div class="p-6 bg-green-50 rounded-2xl">
            <h3 class="font-semibold text-green-800 mb-2"><i class="fas fa-shield-alt mr-2"></i>Гарантия</h3>
            <p class="text-green-700 text-sm">1 год гарантии при соблюдении условий эксплуатации</p>
          </div>
          <div class="p-6 bg-blue-50 rounded-2xl">
            <h3 class="font-semibold text-blue-800 mb-2"><i class="fas fa-truck mr-2"></i>Доставка</h3>
            <p class="text-blue-700 text-sm">Доставка по всей России, особые условия для регионов</p>
          </div>
        </div>
        
        <p class="text-neutral-600 leading-relaxed">
          За годы работы мы реализовали более 500 проектов для клиентов по всей России. 
          Наши специалисты помогут подобрать оптимальное решение под ваши задачи и бюджет.
        </p>
      </div>
    </div>
  </main>

  <footer class="bg-neutral-800 text-white py-8 mt-12">
    <div class="max-w-7xl mx-auto px-6 text-center text-neutral-400 text-sm">
      &copy; 2024 Armata-Rampa. Все права защищены.
    </div>
  </footer>
  `
  
  return c.html(renderPage('О компании', content, 'О компании Armata-Rampa — производитель рамп и эстакад', 
    'Armata-Rampa — российский производитель погрузочных рамп и эстакад с 2010 года. Собственное производство, гарантия качества.'))
})

app.get('/kontakty', async (c) => {
  const settings = c.get('settings')
  
  const content = `
  <header class="bg-white shadow-sm sticky top-0 z-50">
    <div class="max-w-7xl mx-auto">
      <nav class="flex items-center justify-between px-6 py-4">
        <a href="/" class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-lg bg-primary-500 flex items-center justify-center">
            <span class="text-white font-bold">A</span>
          </div>
          <span class="text-lg font-bold text-neutral-800">ARMATA<span class="text-accent-500">RAMPA</span></span>
        </a>
        <div class="hidden lg:flex items-center gap-1">
          <a href="/katalog" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Каталог</a>
          <a href="/o-kompanii" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">О компании</a>
          <a href="/kontakty" class="px-4 py-2 rounded-lg text-primary-600 bg-primary-50 font-medium">Контакты</a>
        </div>
      </nav>
    </div>
  </header>

  <main class="py-12">
    <div class="max-w-4xl mx-auto px-6">
      <h1 class="text-3xl font-bold text-neutral-800 mb-8">Контакты</h1>
      
      <div class="grid md:grid-cols-2 gap-8">
        <div class="space-y-6">
          <div class="p-6 bg-white rounded-2xl shadow-sm">
            <div class="flex items-center gap-4 mb-4">
              <div class="w-12 h-12 rounded-xl bg-primary-100 flex items-center justify-center">
                <i class="fas fa-phone text-xl text-primary-600"></i>
              </div>
              <div>
                <div class="text-sm text-neutral-500">Телефон</div>
                <a href="tel:${settings.phone_main || '+74955553535'}" class="text-lg font-semibold text-neutral-800">${settings.phone_main || '+7 (495) 555-35-35'}</a>
              </div>
            </div>
          </div>
          
          <div class="p-6 bg-white rounded-2xl shadow-sm">
            <div class="flex items-center gap-4 mb-4">
              <div class="w-12 h-12 rounded-xl bg-primary-100 flex items-center justify-center">
                <i class="fas fa-envelope text-xl text-primary-600"></i>
              </div>
              <div>
                <div class="text-sm text-neutral-500">Email</div>
                <a href="mailto:${settings.email || 'info@armata-rampa.ru'}" class="text-lg font-semibold text-neutral-800">${settings.email || 'info@armata-rampa.ru'}</a>
              </div>
            </div>
          </div>
          
          <div class="p-6 bg-white rounded-2xl shadow-sm">
            <div class="flex items-center gap-4 mb-4">
              <div class="w-12 h-12 rounded-xl bg-primary-100 flex items-center justify-center">
                <i class="fas fa-map-marker-alt text-xl text-primary-600"></i>
              </div>
              <div>
                <div class="text-sm text-neutral-500">Адрес</div>
                <div class="text-lg font-semibold text-neutral-800">${settings.address || 'г. Владимир, ул. Промышленная, д. 10'}</div>
              </div>
            </div>
          </div>
          
          <div class="p-6 bg-white rounded-2xl shadow-sm">
            <div class="flex items-center gap-4 mb-4">
              <div class="w-12 h-12 rounded-xl bg-primary-100 flex items-center justify-center">
                <i class="fas fa-clock text-xl text-primary-600"></i>
              </div>
              <div>
                <div class="text-sm text-neutral-500">Режим работы</div>
                <div class="text-lg font-semibold text-neutral-800">${settings.working_hours || 'Пн-Пт: 9:00-18:00'}</div>
              </div>
            </div>
          </div>
        </div>
        
        <div class="bg-white rounded-2xl p-8 shadow-sm">
          <h2 class="text-xl font-semibold text-neutral-800 mb-6">Напишите нам</h2>
          <form id="contactForm" class="space-y-4">
            <input type="text" name="name" required placeholder="Ваше имя" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-primary-500 focus:ring-2 focus:ring-primary-500/20">
            <input type="tel" name="phone" required placeholder="Телефон" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-primary-500 focus:ring-2 focus:ring-primary-500/20">
            <textarea name="message" rows="4" placeholder="Сообщение" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-primary-500 focus:ring-2 focus:ring-primary-500/20 resize-none"></textarea>
            <button type="submit" class="w-full py-3 bg-primary-600 hover:bg-primary-700 text-white font-semibold rounded-xl transition-colors">
              Отправить
            </button>
          </form>
        </div>
      </div>
    </div>
  </main>

  <footer class="bg-neutral-800 text-white py-8 mt-12">
    <div class="max-w-7xl mx-auto px-6 text-center text-neutral-400 text-sm">
      &copy; 2024 Armata-Rampa. Все права защищены.
    </div>
  </footer>
  `
  
  return c.html(renderPage('Контакты', content, 'Контакты | Armata-Rampa', 
    'Контакты компании Armata-Rampa. Телефон, email, адрес производства.'))
})

app.get('/dostavka', async (c) => {
  const content = `
  <header class="bg-white shadow-sm sticky top-0 z-50">
    <div class="max-w-7xl mx-auto">
      <nav class="flex items-center justify-between px-6 py-4">
        <a href="/" class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-lg bg-primary-500 flex items-center justify-center">
            <span class="text-white font-bold">A</span>
          </div>
          <span class="text-lg font-bold text-neutral-800">ARMATA<span class="text-accent-500">RAMPA</span></span>
        </a>
        <div class="hidden lg:flex items-center gap-1">
          <a href="/katalog" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Каталог</a>
          <a href="/dostavka" class="px-4 py-2 rounded-lg text-primary-600 bg-primary-50 font-medium">Доставка</a>
          <a href="/kontakty" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Контакты</a>
        </div>
      </nav>
    </div>
  </header>

  <main class="py-12">
    <div class="max-w-4xl mx-auto px-6">
      <h1 class="text-3xl font-bold text-neutral-800 mb-8">Доставка и оплата</h1>
      
      <div class="space-y-8">
        <div class="bg-white rounded-2xl p-8 shadow-sm">
          <h2 class="text-xl font-semibold text-neutral-800 mb-4"><i class="fas fa-truck text-primary-500 mr-2"></i>Доставка</h2>
          <p class="text-neutral-600 mb-4">Осуществляем доставку по всей России. Особенно выгодные условия для регионов:</p>
          <ul class="grid md:grid-cols-2 gap-2 text-neutral-600">
            <li><i class="fas fa-check text-green-500 mr-2"></i>Владимирская область</li>
            <li><i class="fas fa-check text-green-500 mr-2"></i>Ярославская область</li>
            <li><i class="fas fa-check text-green-500 mr-2"></i>Нижегородская область</li>
            <li><i class="fas fa-check text-green-500 mr-2"></i>Республика Татарстан</li>
            <li><i class="fas fa-check text-green-500 mr-2"></i>Республика Башкортостан</li>
            <li><i class="fas fa-check text-green-500 mr-2"></i>Пермский край</li>
          </ul>
        </div>
        
        <div class="bg-white rounded-2xl p-8 shadow-sm">
          <h2 class="text-xl font-semibold text-neutral-800 mb-4"><i class="fas fa-credit-card text-primary-500 mr-2"></i>Оплата</h2>
          <ul class="space-y-2 text-neutral-600">
            <li><i class="fas fa-check text-green-500 mr-2"></i>Безналичный расчет (для юр. лиц)</li>
            <li><i class="fas fa-check text-green-500 mr-2"></i>Оплата по счету</li>
          </ul>
          <p class="mt-4 text-neutral-500 text-sm">Все цены указаны с НДС 20%.</p>
        </div>
      </div>
    </div>
  </main>

  <footer class="bg-neutral-800 text-white py-8 mt-12">
    <div class="max-w-7xl mx-auto px-6 text-center text-neutral-400 text-sm">
      &copy; 2024 Armata-Rampa. Все права защищены.
    </div>
  </footer>
  `
  
  return c.html(renderPage('Доставка и оплата', content, 'Доставка и оплата | Armata-Rampa', 
    'Условия доставки погрузочных рамп и эстакад по России. Оплата с НДС.'))
})

// Admin login page
app.get('/admin/login', async (c) => {
  return c.html(`<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Вход | Админ-панель</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.5.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-neutral-100 font-sans min-h-screen flex items-center justify-center p-4">
  <div class="w-full max-w-md">
    <div class="text-center mb-8">
      <div class="w-16 h-16 mx-auto rounded-2xl bg-gradient-to-br from-blue-500 to-blue-700 flex items-center justify-center mb-4 shadow-lg">
        <span class="text-3xl font-bold text-white">A</span>
      </div>
      <h1 class="text-2xl font-bold text-neutral-800">Armata-Rampa</h1>
      <p class="text-neutral-500">Вход в админ-панель</p>
    </div>
    
    <div class="bg-white rounded-2xl p-8 shadow-lg">
      <form id="loginForm" class="space-y-5">
        <div id="error-message" class="hidden p-4 rounded-xl bg-red-50 border border-red-200 text-red-600 text-sm"></div>
        
        <div>
          <label class="block text-sm font-medium text-neutral-700 mb-2">Логин</label>
          <input type="text" name="username" required autocomplete="username"
            class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all"
            placeholder="admin">
        </div>
        
        <div>
          <label class="block text-sm font-medium text-neutral-700 mb-2">Пароль</label>
          <input type="password" name="password" required autocomplete="current-password"
            class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all"
            placeholder="Введите пароль">
        </div>
        
        <button type="submit" id="submitBtn"
          class="w-full py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition-colors">
          Войти
        </button>
      </form>
      
      <p class="mt-6 text-center">
        <a href="/" class="text-blue-600 hover:text-blue-700 text-sm">
          <i class="fas fa-arrow-left mr-1"></i> На сайт
        </a>
      </p>
    </div>
  </div>
  
  <script>
    if (localStorage.getItem('adminToken')) {
      window.location.href = '/admin';
    }
    
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const form = e.target;
      const submitBtn = document.getElementById('submitBtn');
      const errorEl = document.getElementById('error-message');
      const formData = new FormData(form);
      
      submitBtn.disabled = true;
      submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Вход...';
      errorEl.classList.add('hidden');
      
      try {
        const response = await fetch('/api/admin/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: formData.get('username'),
            password: formData.get('password')
          })
        });
        
        const data = await response.json();
        
        if (data.success) {
          localStorage.setItem('adminToken', data.token);
          localStorage.setItem('adminUser', JSON.stringify(data.user));
          window.location.href = '/admin';
        } else {
          errorEl.textContent = data.error || 'Ошибка авторизации';
          errorEl.classList.remove('hidden');
        }
      } catch (err) {
        errorEl.textContent = 'Ошибка сети';
        errorEl.classList.remove('hidden');
      } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = 'Войти';
      }
    });
  </script>
</body>
</html>`)
})

// Admin panel
app.get('/admin', async (c) => {
  return c.html(`<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Админ-панель | Armata-Rampa</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.5.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-neutral-100 font-sans">
  <script>
    if (!localStorage.getItem('adminToken')) {
      window.location.href = '/admin/login';
    }
  </script>
  
  <div class="min-h-screen flex">
    <aside class="w-64 bg-white border-r border-neutral-200 flex flex-col">
      <div class="p-6 border-b border-neutral-100">
        <h1 class="text-xl font-bold text-neutral-800">Armata-Rampa</h1>
        <p class="text-neutral-500 text-sm">Админ-панель</p>
      </div>
      <nav class="p-4 space-y-1 flex-1">
        <a href="#dashboard" onclick="showSection('dashboard')" class="flex items-center gap-3 px-4 py-3 rounded-xl bg-blue-50 text-blue-600 font-medium">
          <i class="fas fa-chart-pie w-5"></i> Дашборд
        </a>
        <a href="#products" onclick="showSection('products')" class="flex items-center gap-3 px-4 py-3 rounded-xl text-neutral-600 hover:bg-neutral-50 transition-colors">
          <i class="fas fa-boxes w-5"></i> Товары
        </a>
        <a href="#leads" onclick="showSection('leads')" class="flex items-center gap-3 px-4 py-3 rounded-xl text-neutral-600 hover:bg-neutral-50 transition-colors">
          <i class="fas fa-envelope w-5"></i> Заявки
        </a>
        <a href="#settings" onclick="showSection('settings')" class="flex items-center gap-3 px-4 py-3 rounded-xl text-neutral-600 hover:bg-neutral-50 transition-colors">
          <i class="fas fa-cog w-5"></i> Настройки
        </a>
      </nav>
      <div class="p-4 border-t border-neutral-100">
        <button onclick="logout()" class="w-full px-4 py-2 rounded-xl border border-neutral-200 text-neutral-600 hover:bg-neutral-50 transition-colors text-sm">
          <i class="fas fa-sign-out-alt mr-2"></i> Выйти
        </button>
      </div>
    </aside>

    <main class="flex-1 p-8">
      <section id="section-dashboard" class="admin-section">
        <h2 class="text-2xl font-bold text-neutral-800 mb-6">Дашборд</h2>
        <div class="grid grid-cols-4 gap-6 mb-8">
          <div class="p-6 bg-white rounded-2xl shadow-sm">
            <p class="text-neutral-500 text-sm mb-1">Товаров</p>
            <p id="stat-products" class="text-3xl font-bold text-blue-600">0</p>
          </div>
          <div class="p-6 bg-white rounded-2xl shadow-sm">
            <p class="text-neutral-500 text-sm mb-1">Заявок</p>
            <p id="stat-leads" class="text-3xl font-bold text-green-600">0</p>
          </div>
          <div class="p-6 bg-white rounded-2xl shadow-sm">
            <p class="text-neutral-500 text-sm mb-1">Новых заявок</p>
            <p id="stat-new-leads" class="text-3xl font-bold text-orange-500">0</p>
          </div>
          <div class="p-6 bg-white rounded-2xl shadow-sm">
            <p class="text-neutral-500 text-sm mb-1">Просмотров</p>
            <p id="stat-views" class="text-3xl font-bold text-purple-600">0</p>
          </div>
        </div>
        <div class="bg-white rounded-2xl p-6 shadow-sm">
          <h3 class="font-semibold text-neutral-800 mb-4">Последние заявки</h3>
          <div id="recent-leads" class="space-y-3"></div>
        </div>
      </section>

      <section id="section-products" class="admin-section hidden">
        <div class="flex justify-between items-center mb-6">
          <h2 class="text-2xl font-bold text-neutral-800">Товары</h2>
        </div>
        <div class="bg-white rounded-2xl shadow-sm overflow-hidden">
          <table class="w-full">
            <thead class="bg-neutral-50">
              <tr>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Товар</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Категория</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Цена</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Статус</th>
              </tr>
            </thead>
            <tbody id="products-table" class="divide-y divide-neutral-100"></tbody>
          </table>
        </div>
      </section>

      <section id="section-leads" class="admin-section hidden">
        <h2 class="text-2xl font-bold text-neutral-800 mb-6">Заявки</h2>
        <div class="bg-white rounded-2xl shadow-sm overflow-hidden">
          <table class="w-full">
            <thead class="bg-neutral-50">
              <tr>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Дата</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Имя</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Телефон</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Статус</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Действия</th>
              </tr>
            </thead>
            <tbody id="leads-table" class="divide-y divide-neutral-100"></tbody>
          </table>
        </div>
      </section>

      <section id="section-settings" class="admin-section hidden">
        <h2 class="text-2xl font-bold text-neutral-800 mb-6">Настройки</h2>
        <div class="max-w-xl bg-white rounded-2xl p-6 shadow-sm">
          <form id="settings-form" class="space-y-4">
            <div>
              <label class="block text-sm text-neutral-600 mb-2">Телефон</label>
              <input type="text" name="phone_main" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500">
            </div>
            <div>
              <label class="block text-sm text-neutral-600 mb-2">Email</label>
              <input type="email" name="email" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500">
            </div>
            <div>
              <label class="block text-sm text-neutral-600 mb-2">Адрес</label>
              <input type="text" name="address" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500">
            </div>
            <button type="submit" class="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-xl transition-colors">
              Сохранить
            </button>
          </form>
        </div>
      </section>
    </main>
  </div>

  <script>
    function logout() {
      localStorage.removeItem('adminToken');
      localStorage.removeItem('adminUser');
      window.location.href = '/admin/login';
    }
    
    function showSection(section) {
      document.querySelectorAll('.admin-section').forEach(el => el.classList.add('hidden'));
      document.getElementById('section-' + section).classList.remove('hidden');
      
      document.querySelectorAll('nav a').forEach(a => {
        a.classList.remove('bg-blue-50', 'text-blue-600', 'font-medium');
        a.classList.add('text-neutral-600');
      });
      event.target.closest('a').classList.add('bg-blue-50', 'text-blue-600', 'font-medium');
      event.target.closest('a').classList.remove('text-neutral-600');
    }

    async function loadDashboard() {
      try {
        const [stats, leads] = await Promise.all([
          fetch('/api/admin/stats').then(r => r.json()),
          fetch('/api/admin/leads').then(r => r.json())
        ]);
        
        if (stats.success) {
          document.getElementById('stat-products').textContent = stats.stats.totalProducts;
          document.getElementById('stat-leads').textContent = stats.stats.totalLeads;
          document.getElementById('stat-new-leads').textContent = stats.stats.newLeads;
          document.getElementById('stat-views').textContent = stats.stats.totalViews || 0;
        }
        
        if (leads.success) {
          document.getElementById('recent-leads').innerHTML = (leads.data || []).slice(0, 5).map(lead => 
            '<div class="flex justify-between items-center p-4 bg-neutral-50 rounded-xl"><div><p class="font-medium text-neutral-800">' + lead.name + '</p><p class="text-sm text-neutral-500">' + lead.phone + '</p></div><span class="px-3 py-1 rounded-full text-xs font-medium ' + (lead.status === 'new' ? 'bg-orange-100 text-orange-600' : 'bg-green-100 text-green-600') + '">' + (lead.status === 'new' ? 'Новая' : 'Обработана') + '</span></div>'
          ).join('') || '<p class="text-neutral-500">Заявок пока нет</p>';
        }
      } catch (e) {
        console.error('Error:', e);
      }
    }

    async function loadProducts() {
      const response = await fetch('/api/admin/products');
      const data = await response.json();
      
      document.getElementById('products-table').innerHTML = (data.data || []).map(product => 
        '<tr><td class="px-6 py-4"><div class="font-medium text-neutral-800">' + product.name + '</div></td><td class="px-6 py-4 text-neutral-500">' + (product.category_name || '-') + '</td><td class="px-6 py-4 font-medium">' + (product.price ? product.price.toLocaleString('ru-RU') + ' ₽' : '-') + '</td><td class="px-6 py-4"><span class="px-3 py-1 rounded-full text-xs font-medium ' + (product.is_active ? 'bg-green-100 text-green-600' : 'bg-neutral-100 text-neutral-500') + '">' + (product.is_active ? 'Активен' : 'Скрыт') + '</span></td></tr>'
      ).join('') || '<tr><td colspan="4" class="px-6 py-8 text-center text-neutral-500">Товаров нет</td></tr>';
    }

    async function loadLeads() {
      const response = await fetch('/api/admin/leads');
      const data = await response.json();
      
      document.getElementById('leads-table').innerHTML = (data.data || []).map(lead => 
        '<tr><td class="px-6 py-4 text-sm text-neutral-500">' + new Date(lead.created_at).toLocaleString('ru-RU') + '</td><td class="px-6 py-4 font-medium text-neutral-800">' + lead.name + '</td><td class="px-6 py-4">' + lead.phone + '</td><td class="px-6 py-4"><select onchange="updateLeadStatus(' + lead.id + ', this.value)" class="px-3 py-1 rounded-lg border border-neutral-200 text-sm"><option value="new"' + (lead.status === 'new' ? ' selected' : '') + '>Новая</option><option value="processing"' + (lead.status === 'processing' ? ' selected' : '') + '>В работе</option><option value="completed"' + (lead.status === 'completed' ? ' selected' : '') + '>Завершена</option></select></td><td class="px-6 py-4"><a href="tel:' + lead.phone + '" class="text-green-600 hover:text-green-700"><i class="fas fa-phone"></i></a></td></tr>'
      ).join('') || '<tr><td colspan="5" class="px-6 py-8 text-center text-neutral-500">Заявок нет</td></tr>';
    }

    async function updateLeadStatus(id, status) {
      await fetch('/api/admin/leads/' + id, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status })
      });
      loadLeads();
      loadDashboard();
    }

    async function loadSettings() {
      const response = await fetch('/api/settings');
      const data = await response.json();
      const settings = data.data || {};
      
      const form = document.getElementById('settings-form');
      Object.keys(settings).forEach(key => {
        const input = form.querySelector('[name="' + key + '"]');
        if (input) input.value = settings[key];
      });
    }

    document.getElementById('settings-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(e.target);
      const settings = Object.fromEntries(formData);
      
      await fetch('/api/admin/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings)
      });
      
      alert('Настройки сохранены');
    });

    loadDashboard();
    loadProducts();
    loadLeads();
    loadSettings();
  </script>
</body>
</html>`)
})

export default app
