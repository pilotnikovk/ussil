import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { serveStatic } from 'hono/cloudflare-pages'

// Types
type Bindings = {
  DB: D1Database
  JWT_SECRET: string
  RESEND_API_KEY: string
  ADMIN_EMAIL: string
  R2_BUCKET: R2Bucket
  TELEGRAM_BOT_TOKEN: string
  TELEGRAM_CHAT_ID: string
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
// SITEMAP & ROBOTS
// ==========================================

// Auto-generated sitemap.xml
app.get('/sitemap.xml', async (c) => {
  const settings = c.get('settings')
  const baseUrl = settings.site_url || 'https://ussil.ru'
  
  // Get all products
  let products: any[] = []
  try {
    const result = await c.env.DB.prepare('SELECT slug, updated_at FROM products WHERE is_active = 1').all()
    products = result.results || []
  } catch (e) {}
  
  // Get all categories
  let categories: any[] = []
  try {
    const result = await c.env.DB.prepare('SELECT slug, updated_at FROM categories WHERE is_active = 1').all()
    categories = result.results || []
  } catch (e) {}
  
  // Get all pages
  let pages: any[] = []
  try {
    const result = await c.env.DB.prepare('SELECT slug, updated_at FROM pages WHERE is_active = 1').all()
    pages = result.results || []
  } catch (e) {}
  
  const today = new Date().toISOString().split('T')[0]
  
  const staticPages = [
    { url: '/', priority: '1.0', changefreq: 'daily' },
    { url: '/katalog', priority: '0.9', changefreq: 'daily' },
    { url: '/kejsy', priority: '0.8', changefreq: 'weekly' },
    { url: '/o-kompanii', priority: '0.7', changefreq: 'monthly' },
    { url: '/dostavka', priority: '0.7', changefreq: 'monthly' },
    { url: '/kontakty', priority: '0.7', changefreq: 'monthly' }
  ]
  
  let xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${staticPages.map(p => `  <url>
    <loc>${baseUrl}${p.url}</loc>
    <lastmod>${today}</lastmod>
    <changefreq>${p.changefreq}</changefreq>
    <priority>${p.priority}</priority>
  </url>`).join('\n')}
${categories.map((cat: any) => `  <url>
    <loc>${baseUrl}/katalog?category=${cat.slug}</loc>
    <lastmod>${cat.updated_at ? cat.updated_at.split('T')[0] : today}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>`).join('\n')}
${products.map((prod: any) => `  <url>
    <loc>${baseUrl}/product/${prod.slug}</loc>
    <lastmod>${prod.updated_at ? prod.updated_at.split('T')[0] : today}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>`).join('\n')}
</urlset>`

  return c.text(xml, 200, { 'Content-Type': 'application/xml' })
})

// Robots.txt
app.get('/robots.txt', (c) => {
  const settings = c.get('settings')
  const baseUrl = settings.site_url || 'https://ussil.ru'
  
  return c.text(`User-agent: *
Allow: /
Disallow: /admin
Disallow: /api/admin

Sitemap: ${baseUrl}/sitemap.xml`, 200, { 'Content-Type': 'text/plain' })
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

// Send Telegram notification
const sendTelegramNotification = async (env: Bindings, lead: any) => {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return
  
  try {
    const message = `🔔 *Новая заявка с сайта USSIL*

👤 *Имя:* ${lead.name}
📞 *Телефон:* ${lead.phone}${lead.email ? `\n📧 *Email:* ${lead.email}` : ''}${lead.company ? `\n🏢 *Компания:* ${lead.company}` : ''}${lead.message ? `\n💬 *Сообщение:* ${lead.message}` : ''}${lead.source ? `\n📍 *Источник:* ${lead.source}` : ''}

⏰ ${new Date().toLocaleString('ru-RU', { timeZone: 'Europe/Moscow' })}`

    await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: env.TELEGRAM_CHAT_ID,
        text: message,
        parse_mode: 'Markdown'
      })
    })
  } catch (e) {
    console.error('Failed to send Telegram notification:', e)
  }
}

// Send email notification via Resend API
const sendEmailNotification = async (env: Bindings, lead: any) => {
  // Always try to send Telegram notification
  sendTelegramNotification(env, lead)
  
  if (!env.RESEND_API_KEY || !env.ADMIN_EMAIL) return
  
  try {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: 'USSIL <noreply@ussil.ru>',
        to: [env.ADMIN_EMAIL],
        subject: `Новая заявка от ${lead.name}`,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #1e40af;">Новая заявка с сайта USSIL</h2>
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

// Admin Categories CRUD
app.get('/api/admin/categories', async (c) => {
  try {
    const result = await c.env.DB.prepare('SELECT * FROM categories ORDER BY sort_order').all()
    return c.json({ success: true, data: result.results })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to fetch categories' }, 500)
  }
})

app.post('/api/admin/categories', async (c) => {
  try {
    const { name, slug, description, seo_title, seo_description, seo_keywords, image_url, sort_order, is_active } = await c.req.json()
    
    const result = await c.env.DB.prepare(`
      INSERT INTO categories (name, slug, description, seo_title, seo_description, seo_keywords, image_url, sort_order, is_active)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(name, slug, description || '', seo_title || '', seo_description || '', seo_keywords || '', image_url || '', sort_order || 0, is_active ? 1 : 0).run()
    
    return c.json({ success: true, id: result.meta.last_row_id })
  } catch (e: any) {
    return c.json({ success: false, error: e.message || 'Failed to create category' }, 500)
  }
})

app.put('/api/admin/categories/:id', async (c) => {
  try {
    const id = c.req.param('id')
    const { name, slug, description, seo_title, seo_description, seo_keywords, image_url, sort_order, is_active } = await c.req.json()
    
    await c.env.DB.prepare(`
      UPDATE categories SET name = ?, slug = ?, description = ?, seo_title = ?, seo_description = ?, seo_keywords = ?, image_url = ?, sort_order = ?, is_active = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).bind(name, slug, description || '', seo_title || '', seo_description || '', seo_keywords || '', image_url || '', sort_order || 0, is_active ? 1 : 0, id).run()
    
    return c.json({ success: true })
  } catch (e: any) {
    return c.json({ success: false, error: e.message || 'Failed to update category' }, 500)
  }
})

app.delete('/api/admin/categories/:id', async (c) => {
  try {
    const id = c.req.param('id')
    await c.env.DB.prepare('DELETE FROM categories WHERE id = ?').bind(id).run()
    return c.json({ success: true })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to delete category' }, 500)
  }
})

// Cases API
app.get('/api/cases', async (c) => {
  try {
    const result = await c.env.DB.prepare('SELECT * FROM cases WHERE is_active = 1 ORDER BY sort_order').all()
    return c.json({ success: true, data: result.results })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to fetch cases' }, 500)
  }
})

app.get('/api/admin/cases', async (c) => {
  try {
    const result = await c.env.DB.prepare('SELECT * FROM cases ORDER BY sort_order').all()
    return c.json({ success: true, data: result.results })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to fetch cases' }, 500)
  }
})

app.post('/api/admin/cases', async (c) => {
  try {
    const { title, description, client_name, client_logo, location, completion_date, result_text, main_image, images, sort_order, is_active } = await c.req.json()
    const result = await c.env.DB.prepare(`
      INSERT INTO cases (title, description, client_name, client_logo, location, completion_date, result_text, main_image, images, sort_order, is_active)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(title, description || '', client_name || '', client_logo || '', location || '', completion_date || '', result_text || '', main_image || '', JSON.stringify(images || []), sort_order || 0, is_active ? 1 : 0).run()
    return c.json({ success: true, id: result.meta.last_row_id })
  } catch (e: any) {
    return c.json({ success: false, error: e.message || 'Failed to create case' }, 500)
  }
})

app.put('/api/admin/cases/:id', async (c) => {
  try {
    const id = c.req.param('id')
    const { title, description, client_name, client_logo, location, completion_date, result_text, main_image, images, sort_order, is_active } = await c.req.json()
    await c.env.DB.prepare(`
      UPDATE cases SET title = ?, description = ?, client_name = ?, client_logo = ?, location = ?, completion_date = ?, result_text = ?, main_image = ?, images = ?, sort_order = ?, is_active = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).bind(title, description || '', client_name || '', client_logo || '', location || '', completion_date || '', result_text || '', main_image || '', JSON.stringify(images || []), sort_order || 0, is_active ? 1 : 0, id).run()
    return c.json({ success: true })
  } catch (e: any) {
    return c.json({ success: false, error: e.message || 'Failed to update case' }, 500)
  }
})

app.delete('/api/admin/cases/:id', async (c) => {
  try {
    const id = c.req.param('id')
    await c.env.DB.prepare('DELETE FROM cases WHERE id = ?').bind(id).run()
    return c.json({ success: true })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to delete case' }, 500)
  }
})

// Partners API
app.get('/api/partners', async (c) => {
  try {
    const result = await c.env.DB.prepare('SELECT * FROM partners WHERE is_active = 1 ORDER BY sort_order').all()
    return c.json({ success: true, data: result.results })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to fetch partners' }, 500)
  }
})

app.get('/api/admin/partners', async (c) => {
  try {
    const result = await c.env.DB.prepare('SELECT * FROM partners ORDER BY sort_order').all()
    return c.json({ success: true, data: result.results })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to fetch partners' }, 500)
  }
})

app.post('/api/admin/partners', async (c) => {
  try {
    const { name, logo_url, website_url, description, sort_order, is_active } = await c.req.json()
    const result = await c.env.DB.prepare(`
      INSERT INTO partners (name, logo_url, website_url, description, sort_order, is_active)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(name, logo_url || '', website_url || '', description || '', sort_order || 0, is_active ? 1 : 0).run()
    return c.json({ success: true, id: result.meta.last_row_id })
  } catch (e: any) {
    return c.json({ success: false, error: e.message || 'Failed to create partner' }, 500)
  }
})

app.put('/api/admin/partners/:id', async (c) => {
  try {
    const id = c.req.param('id')
    const { name, logo_url, website_url, description, sort_order, is_active } = await c.req.json()
    await c.env.DB.prepare(`
      UPDATE partners SET name = ?, logo_url = ?, website_url = ?, description = ?, sort_order = ?, is_active = ?
      WHERE id = ?
    `).bind(name, logo_url || '', website_url || '', description || '', sort_order || 0, is_active ? 1 : 0, id).run()
    return c.json({ success: true })
  } catch (e: any) {
    return c.json({ success: false, error: e.message || 'Failed to update partner' }, 500)
  }
})

app.delete('/api/admin/partners/:id', async (c) => {
  try {
    const id = c.req.param('id')
    await c.env.DB.prepare('DELETE FROM partners WHERE id = ?').bind(id).run()
    return c.json({ success: true })
  } catch (e) {
    return c.json({ success: false, error: 'Failed to delete partner' }, 500)
  }
})

// Image Upload API - uses Cloudflare R2 if available, fallback to base64
app.post('/api/admin/upload', async (c) => {
  try {
    const formData = await c.req.formData()
    const file = formData.get('file') as File
    
    if (!file) {
      return c.json({ success: false, error: 'No file provided' }, 400)
    }
    
    // Validate file type
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml']
    if (!allowedTypes.includes(file.type)) {
      return c.json({ success: false, error: 'Недопустимый тип файла. Разрешены: JPEG, PNG, GIF, WebP, SVG' }, 400)
    }
    
    // Max 10MB
    if (file.size > 10 * 1024 * 1024) {
      return c.json({ success: false, error: 'Файл слишком большой. Максимум 10 МБ' }, 400)
    }
    
    const arrayBuffer = await file.arrayBuffer()
    const timestamp = Date.now()
    const ext = file.name.split('.').pop() || 'jpg'
    const filename = `${timestamp}-${Math.random().toString(36).substring(7)}.${ext}`
    
    // Helper function to convert ArrayBuffer to base64 without stack overflow
    function arrayBufferToBase64(buffer: ArrayBuffer): string {
      const bytes = new Uint8Array(buffer)
      const chunkSize = 8192
      let binary = ''
      for (let i = 0; i < bytes.length; i += chunkSize) {
        const chunk = bytes.subarray(i, Math.min(i + chunkSize, bytes.length))
        binary += String.fromCharCode.apply(null, chunk as any)
      }
      return btoa(binary)
    }
    
    let imageUrl: string
    
    // Try to use R2 if available and properly configured
    const r2Bucket = c.env.R2_BUCKET
    if (r2Bucket && typeof r2Bucket.put === 'function') {
      try {
        await r2Bucket.put(`uploads/${filename}`, arrayBuffer, {
          httpMetadata: {
            contentType: file.type
          }
        })
        // R2 public URL - configure in Cloudflare Dashboard
        const settings = c.get('settings')
        const r2Domain = settings.r2_public_domain
        if (r2Domain) {
          imageUrl = `${r2Domain}/uploads/${filename}`
        } else {
          // No public domain configured, use base64
          imageUrl = 'data:' + file.type + ';base64,' + arrayBufferToBase64(arrayBuffer)
        }
      } catch (r2Error) {
        console.error('R2 upload failed, falling back to base64:', r2Error)
        // Fallback to base64
        imageUrl = 'data:' + file.type + ';base64,' + arrayBufferToBase64(arrayBuffer)
      }
    } else {
      // No R2 configured - use base64 data URL
      imageUrl = 'data:' + file.type + ';base64,' + arrayBufferToBase64(arrayBuffer)
    }
    
    // Store in database
    const result = await c.env.DB.prepare(`
      INSERT INTO uploads (filename, original_name, mime_type, size, url)
      VALUES (?, ?, ?, ?, ?)
    `).bind(filename, file.name, file.type, file.size, imageUrl).run()
    
    return c.json({ 
      success: true, 
      url: imageUrl,
      id: result.meta.last_row_id,
      filename: file.name 
    })
  } catch (e: any) {
    return c.json({ success: false, error: e.message || 'Upload failed' }, 500)
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

const renderPage = (title: string, content: string, seoTitle?: string, seoDescription?: string, settings?: Record<string, string>) => {
  const siteName = settings?.site_name || 'USSIL'
  return `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${seoTitle || title} | ${siteName}</title>
  <meta name="description" content="${seoDescription || 'Производитель погрузочных рамп и эстакад. Собственное производство, гарантия качества, доставка по России.'}">
  <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
  
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
              50: '#f0f9ff', 100: '#e0f2fe', 200: '#bae6fd', 300: '#7dd3fc',
              400: '#38bdf8', 500: '#0ea5e9', 600: '#0284c7', 700: '#0369a1',
              800: '#075985', 900: '#0c4a6e'
            },
            accent: {
              50: '#fef3c7', 100: '#fde68a', 200: '#fcd34d', 300: '#fbbf24',
              400: '#f59e0b', 500: '#d97706', 600: '#b45309', 700: '#92400e'
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
  {"@context":"https://schema.org","@type":"Organization","name":"${siteName}","description":"Производитель погрузочных рамп и эстакад","url":"https://ussil.ru"}
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
  const siteName = settings.site_name || 'USSIL'
  const logoUrl = settings.logo_url || 'https://www.genspark.ai/api/files/s/eBVbsOpD'
  const heroBgImage = settings.hero_bg_image || 'https://images.unsplash.com/photo-1586528116311-ad8dd3c8310d?w=1920&h=1080&fit=crop'
  
  // Block visibility settings (default to true if not set)
  const showCategories = settings.block_categories !== '0' && settings.block_categories !== 'false'
  const showProducts = settings.block_products !== '0' && settings.block_products !== 'false'
  const showAdvantages = settings.block_advantages !== '0' && settings.block_advantages !== 'false'
  const showReviews = settings.block_reviews !== '0' && settings.block_reviews !== 'false'
  const showContactForm = settings.block_contact_form !== '0' && settings.block_contact_form !== 'false'
  const showCases = settings.block_cases !== '0' && settings.block_cases !== 'false'
  const showWhatsApp = settings.block_whatsapp !== '0' && settings.block_whatsapp !== 'false'
  
  // Load cases and partners
  let cases: any[] = []
  let partners: any[] = []
  try {
    const casesResult = await c.env.DB.prepare('SELECT * FROM cases WHERE is_active = 1 ORDER BY sort_order LIMIT 6').all()
    cases = casesResult.results || []
  } catch (e) {}
  try {
    const partnersResult = await c.env.DB.prepare('SELECT * FROM partners WHERE is_active = 1 ORDER BY sort_order').all()
    partners = partnersResult.results || []
  } catch (e) {}
  
  const content = `
  <!-- Header -->
  <header class="bg-white shadow-sm sticky top-0 z-50">
    <div class="max-w-7xl mx-auto">
      <div class="hidden lg:flex items-center justify-between px-6 py-2 border-b border-neutral-100 text-sm">
        <div class="flex items-center gap-6 text-neutral-600">
          <span><i class="fas fa-map-marker-alt text-primary-500 mr-2"></i>${settings.address || 'г. Ковров, ул. Свердлова, 108А'}</span>
          <span><i class="fas fa-clock text-primary-500 mr-2"></i>${settings.working_hours || 'Пн-Пт: 9:00-18:00'}</span>
        </div>
        <div class="flex items-center gap-4">
          <a href="mailto:${settings.email || 'info@ussil.ru'}" class="text-neutral-600 hover:text-primary-600 transition-colors">
            <i class="fas fa-envelope mr-2"></i>${settings.email || 'info@ussil.ru'}
          </a>
        </div>
      </div>
      
      <nav class="flex items-center justify-between px-6 py-4">
        <a href="/" class="flex items-center gap-3">
          <img src="${logoUrl}" alt="${siteName}" class="h-10 w-auto">
          <span class="text-2xl font-bold text-neutral-800">${siteName}</span>
        </a>
        
        <div class="hidden lg:flex items-center gap-1">
          <a href="/katalog" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Каталог</a>
          <a href="/o-kompanii" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">О компании</a>
          <a href="/kejsy" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Кейсы</a>
          <a href="/dostavka" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Доставка</a>
          <a href="/kontakty" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Контакты</a>
        </div>
        
        <div class="flex items-center gap-2 lg:gap-4">
          <a href="https://wa.me/${(settings.phone_whatsapp || '89209160100').replace(/[^0-9]/g, '')}" target="_blank" class="hidden md:flex w-12 h-12 rounded-xl bg-green-500 hover:bg-green-600 items-center justify-center transition-colors" title="Написать в WhatsApp">
            <i class="fab fa-whatsapp text-white text-xl"></i>
          </a>
          <a href="https://t.me/${(settings.telegram || 'max_ussil').replace('@', '')}" target="_blank" class="hidden md:flex w-12 h-12 rounded-xl bg-blue-500 hover:bg-blue-600 items-center justify-center transition-colors" title="Написать в Telegram (Макс)">
            <i class="fab fa-telegram text-white text-xl"></i>
          </a>
          <a href="tel:${(settings.phone_main || '84923225431').replace(/[^+\d]/g, '')}" class="hidden md:flex items-center gap-3">
            <div class="w-12 h-12 rounded-xl bg-primary-50 flex items-center justify-center">
              <i class="fas fa-phone text-primary-600"></i>
            </div>
            <div>
              <div class="text-xs text-neutral-500">Звоните</div>
              <div class="font-semibold text-neutral-800">${settings.phone_main || '8 (49232) 2-54-31'}</div>
            </div>
          </a>
          <a href="#contact-form" class="hidden sm:inline-flex px-6 py-3 bg-accent-500 hover:bg-accent-600 text-white font-semibold rounded-xl shadow-lg shadow-accent-500/30 transition-all">
            Оставить заявку
          </a>
          <button onclick="toggleMobileMenu()" class="lg:hidden w-12 h-12 rounded-xl bg-neutral-100 flex items-center justify-center">
            <i class="fas fa-bars text-neutral-600"></i>
          </button>
        </div>
      </nav>
      <!-- Mobile Menu -->
      <div id="mobileMenu" class="hidden lg:hidden border-t border-neutral-100 bg-white">
        <div class="px-6 py-4 space-y-2">
          <a href="/katalog" class="block px-4 py-3 rounded-lg text-neutral-600 hover:bg-neutral-50 font-medium">Каталог</a>
          <a href="/o-kompanii" class="block px-4 py-3 rounded-lg text-neutral-600 hover:bg-neutral-50 font-medium">О компании</a>
          <a href="/kejsy" class="block px-4 py-3 rounded-lg text-neutral-600 hover:bg-neutral-50 font-medium">Кейсы</a>
          <a href="/dostavka" class="block px-4 py-3 rounded-lg text-neutral-600 hover:bg-neutral-50 font-medium">Доставка</a>
          <a href="/kontakty" class="block px-4 py-3 rounded-lg text-neutral-600 hover:bg-neutral-50 font-medium">Контакты</a>
          <a href="#contact-form" class="block px-4 py-3 rounded-lg bg-accent-500 text-white text-center font-semibold mt-4">
            <i class="fas fa-paper-plane mr-2"></i>Оставить заявку
          </a>
        </div>
      </div>
    </div>
  </header>

  <!-- Hero Section with Background Image -->
  <section class="relative min-h-[600px] lg:min-h-[700px] flex items-center overflow-hidden">
    <!-- Background Image with Overlay -->
    <div class="absolute inset-0">
      <img src="${heroBgImage}" alt="Складской терминал" class="w-full h-full object-cover">
      <div class="absolute inset-0 bg-gradient-to-r from-neutral-900/90 via-neutral-900/70 to-neutral-900/50"></div>
    </div>
    
    <div class="relative max-w-7xl mx-auto px-6 py-20 lg:py-28">
      <div class="max-w-3xl">
        <div class="inline-flex items-center gap-2 px-4 py-2 bg-white/10 backdrop-blur rounded-full text-white/90 text-sm mb-6">
          <i class="fas fa-award"></i>
          <span>Производитель с 2010 года</span>
        </div>
        
        <h1 class="text-4xl lg:text-6xl font-bold text-white mb-6 leading-tight">
          ${settings.hero_title || 'Погрузочные рампы и эстакады'}
          <span class="text-accent-400">${settings.hero_subtitle || 'от производителя'}</span>
        </h1>
        
        <p class="text-xl text-white/80 mb-8 leading-relaxed">
          ${settings.hero_description || 'Собственное производство Владимирская область, г. Ковров. Гарантия 24 месяца. Доставка по всей России.'}
        </p>
        
        <div class="flex flex-wrap gap-4">
          <a href="/katalog" class="inline-flex items-center gap-2 px-8 py-4 bg-white text-neutral-800 font-semibold rounded-xl hover:bg-neutral-100 transition-all shadow-xl">
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
            <div class="text-3xl font-bold text-white">${settings.hero_stat1_value || '500+'}</div>
            <div class="text-white/70">${settings.hero_stat1_label || 'Проектов'}</div>
          </div>
          <div>
            <div class="text-3xl font-bold text-white">${settings.hero_stat2_value || '12 лет'}</div>
            <div class="text-white/70">${settings.hero_stat2_label || 'На рынке'}</div>
          </div>
          <div>
            <div class="text-3xl font-bold text-white">${settings.guarantee_years || '24'} мес</div>
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

  ${showCategories ? `
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
  ` : ''}

  ${showProducts ? `
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
  ` : ''}

  ${showAdvantages ? `
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
          <p class="text-neutral-600 text-sm">Владимирская область, г. Ковров. Контролируем качество на всех этапах</p>
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
          <h3 class="text-lg font-semibold text-neutral-800 mb-2">Гарантия 24 месяца</h3>
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
  ` : ''}

  ${showReviews ? `
  <!-- Reviews Section -->
  <section class="py-16 lg:py-24 bg-neutral-100">
    <div class="max-w-7xl mx-auto px-6">
      <div class="text-center mb-12">
        <h2 class="text-3xl lg:text-4xl font-bold text-neutral-800 mb-4">Отзывы клиентов</h2>
        <p class="text-neutral-600 max-w-2xl mx-auto">Что говорят о нас наши клиенты</p>
      </div>
      
      <div id="reviews-grid" class="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
        <!-- Reviews loaded via JS -->
      </div>
    </div>
  </section>
  ` : ''}

  ${showContactForm ? `
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
                <a href="tel:${settings.phone_main || '84923225431'}" class="text-white font-semibold">${settings.phone_main || '8 (49232) 2-54-31'}</a>
              </div>
            </div>
            <div class="flex items-center gap-4">
              <div class="w-12 h-12 rounded-xl bg-white/10 flex items-center justify-center">
                <i class="fas fa-envelope text-white"></i>
              </div>
              <div>
                <div class="text-white/60 text-sm">Email</div>
                <a href="mailto:${settings.email || 'info@ussil.ru'}" class="text-white font-semibold">${settings.email || 'info@ussil.ru'}</a>
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
  ` : ''}

  ${showCases && cases.length > 0 ? `
  <!-- Cases Section -->
  <section class="py-16 lg:py-24 bg-white">
    <div class="max-w-7xl mx-auto px-6">
      <div class="flex flex-col md:flex-row md:items-end md:justify-between mb-12">
        <div>
          <h2 class="text-3xl lg:text-4xl font-bold text-neutral-800 mb-4">Наши кейсы</h2>
          <p class="text-neutral-600">Реализованные проекты для ведущих компаний России</p>
        </div>
        <a href="/kejsy" class="inline-flex items-center gap-2 text-primary-600 font-semibold hover:text-primary-700 mt-4 md:mt-0">
          Все кейсы <i class="fas fa-arrow-right"></i>
        </a>
      </div>
      
      <div class="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
        ${cases.map((item: any) => `
        <div class="group bg-white rounded-2xl overflow-hidden shadow-sm hover:shadow-xl transition-all border border-neutral-100">
          <div class="relative h-48 overflow-hidden">
            <img src="${item.main_image || 'https://images.unsplash.com/photo-1586528116311-ad8dd3c8310d?w=600&h=400&fit=crop'}" alt="${item.title}" class="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500">
            <div class="absolute inset-0 bg-gradient-to-t from-black/60 to-transparent"></div>
            <div class="absolute bottom-4 left-4 right-4">
              <span class="px-3 py-1 bg-white/90 backdrop-blur text-xs font-medium rounded-full text-neutral-700">${item.client_name || ''}</span>
            </div>
          </div>
          <div class="p-6">
            <h3 class="text-lg font-semibold text-neutral-800 mb-2">${item.title}</h3>
            <p class="text-neutral-600 text-sm mb-3 line-clamp-2">${item.description || ''}</p>
            ${item.location ? `<div class="flex items-center gap-2 text-xs text-neutral-500"><i class="fas fa-map-marker-alt"></i>${item.location}</div>` : ''}
          </div>
        </div>
        `).join('')}
      </div>
    </div>
  </section>
  ` : ''}

  <!-- Footer -->
  <footer class="bg-neutral-800 text-white py-12">
    <div class="max-w-7xl mx-auto px-6">
      <div class="grid md:grid-cols-4 gap-8 mb-8">
        <div>
          <div class="flex items-center gap-3 mb-4">
            <img src="${logoUrl}" alt="${siteName}" class="h-8 w-auto brightness-0 invert">
            <span class="text-lg font-bold">${siteName}</span>
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
            <li><a href="/kejsy" class="hover:text-white transition-colors">Кейсы</a></li>
            <li><a href="/dostavka" class="hover:text-white transition-colors">Доставка и оплата</a></li>
            <li><a href="/kontakty" class="hover:text-white transition-colors">Контакты</a></li>
          </ul>
        </div>
        
        <div>
          <h4 class="font-semibold mb-4">Контакты</h4>
          <ul class="space-y-2 text-neutral-400 text-sm">
            <li><i class="fas fa-phone mr-2 text-primary-400"></i><a href="tel:84923225431" class="hover:text-white">8 (49232) 2-54-31</a> <span class="text-neutral-500">(городской)</span></li>
            <li><i class="fas fa-mobile-alt mr-2 text-primary-400"></i><a href="tel:89209160100" class="hover:text-white">8-920-916-01-00</a> <span class="text-neutral-500">(сотовый)</span></li>
            <li><i class="fab fa-telegram mr-2 text-primary-400"></i><a href="https://t.me/${settings.telegram || 'max_ussil'}" class="hover:text-white" target="_blank">Telegram</a></li>
            <li><i class="fas fa-envelope mr-2 text-primary-400"></i><a href="mailto:${settings.email || 'info@ussil.ru'}" class="hover:text-white">${settings.email || 'info@ussil.ru'}</a></li>
            <li><i class="fas fa-map-marker-alt mr-2 text-primary-400"></i>${settings.address || 'Владимирская обл., г. Ковров, ул. Свердлова, 108А'}</li>
          </ul>
        </div>
      </div>
      
      <div class="pt-8 border-t border-neutral-700 text-center text-neutral-500 text-sm">
        &copy; ${new Date().getFullYear()} ${siteName}. Все права защищены.
      </div>
    </div>
  </footer>
  
  ${showWhatsApp ? `
  <!-- Floating Messenger Buttons -->
  <div class="fixed bottom-6 right-6 z-50 flex flex-col gap-3">
    <a href="https://t.me/${(settings.telegram || 'max_ussil').replace('@', '')}?text=${encodeURIComponent('Здравствуйте! Интересует информация о погрузочных рампах.')}" 
       target="_blank" 
       class="w-14 h-14 bg-blue-500 hover:bg-blue-600 rounded-full flex items-center justify-center shadow-2xl hover:scale-110 transition-all"
       title="Написать в Telegram (Макс)">
      <i class="fab fa-telegram text-white text-2xl"></i>
    </a>
    <a href="https://wa.me/${(settings.phone_whatsapp || '89209160100').replace(/[^0-9]/g, '')}?text=${encodeURIComponent('Здравствуйте! Интересует информация о погрузочных рампах.')}" 
       target="_blank" 
       class="w-14 h-14 bg-green-500 hover:bg-green-600 rounded-full flex items-center justify-center shadow-2xl hover:scale-110 transition-all"
       title="Написать в WhatsApp">
      <i class="fab fa-whatsapp text-white text-2xl"></i>
    </a>
  </div>
  ` : ''}
  
  <script>
    function toggleMobileMenu() {
      const menu = document.getElementById('mobileMenu');
      menu.classList.toggle('hidden');
    }
    
    // Load categories
    async function loadCategories() {
      const grid = document.getElementById('categories-grid');
      if (!grid) return;
      try {
        const response = await fetch('/api/categories');
        const data = await response.json();
        if (data.success && data.data) {
          grid.innerHTML = data.data.map(cat => \`
            <a href="/katalog/\${cat.slug}" class="group p-8 bg-white rounded-2xl shadow-sm hover:shadow-xl transition-all border border-neutral-100">
              <div class="w-16 h-16 rounded-2xl bg-primary-100 flex items-center justify-center mb-6 group-hover:bg-primary-500 transition-colors">
                <i class="fas fa-box text-3xl text-primary-600 group-hover:text-white"></i>
              </div>
              <h3 class="text-xl font-semibold text-neutral-800 mb-2 group-hover:text-primary-600">\${cat.name}</h3>
              <p class="text-neutral-600 text-sm">\${cat.description || ''}</p>
            </a>
          \`).join('');
        }
      } catch(e) { console.error('Error loading categories', e); }
    }
    
    // Load products
    async function loadProducts() {
      const grid = document.getElementById('featured-products');
      if (!grid) return;
      try {
        const response = await fetch('/api/products');
        const data = await response.json();
        if (data.success && data.data) {
          const products = data.data.slice(0, 6);
          grid.innerHTML = products.map(p => {
            const priceWithVAT = p.price ? Math.round(p.price * 1.22) : null;
            return \`
            <a href="/product/\${p.slug}" class="group bg-white rounded-2xl shadow-sm hover:shadow-xl transition-all overflow-hidden">
              <div class="aspect-video overflow-hidden">
                <img src="\${p.main_image || 'https://images.unsplash.com/photo-1586528116311-ad8dd3c8310d?w=600&h=400&fit=crop'}" 
                     alt="\${p.name}" class="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300">
              </div>
              <div class="p-6">
                \${p.is_hit ? '<span class="inline-block px-3 py-1 bg-accent-100 text-accent-700 text-xs font-semibold rounded-full mb-3">Хит продаж</span>' : ''}
                <h3 class="text-lg font-semibold text-neutral-800 mb-2 group-hover:text-primary-600">\${p.name}</h3>
                <p class="text-neutral-600 text-sm mb-4">\${p.short_description || ''}</p>
                <div class="flex flex-col">
                  <span class="text-2xl font-bold text-primary-600">\${priceWithVAT ? priceWithVAT.toLocaleString('ru-RU') + ' ₽' : 'По запросу'}</span>
                  <span class="text-xs text-neutral-400 mt-1">с НДС 22%</span>
                </div>
              </div>
            </a>
          \`}).join('');
        }
      } catch(e) { console.error('Error loading products', e); }
    }
    
    // Load reviews
    async function loadReviews() {
      const grid = document.getElementById('reviews-grid');
      if (!grid) return;
      try {
        const response = await fetch('/api/reviews');
        const data = await response.json();
        if (data.success && data.data) {
          const reviews = data.data.slice(0, 6);
          grid.innerHTML = reviews.map(r => \`
            <div class="bg-white p-6 rounded-2xl shadow-sm">
              <div class="flex items-center gap-1 mb-4">
                \${Array(5).fill().map((_, i) => \`<i class="fas fa-star \${i < r.rating ? 'text-yellow-400' : 'text-neutral-200'}"></i>\`).join('')}
              </div>
              <p class="text-neutral-700 mb-4 line-clamp-4">"\${r.review_text}"</p>
              <div class="border-t border-neutral-100 pt-4">
                <div class="font-semibold text-neutral-800">\${r.client_name}</div>
                \${r.client_company ? \`<div class="text-sm text-neutral-500">\${r.client_company}\${r.client_position ? ', ' + r.client_position : ''}</div>\` : ''}
              </div>
            </div>
          \`).join('');
        }
      } catch(e) { console.error('Error loading reviews', e); }
    }
    
    // Load on page load
    document.addEventListener('DOMContentLoaded', () => {
      loadCategories();
      loadProducts();
      loadReviews();
    });
  </script>
  `
  
  return c.html(renderPage('Главная', content, siteName + ' — Погрузочные рампы и эстакады от производителя', 
    'Производитель погрузочных рамп и эстакад. Собственное производство Владимирская область, г. Ковров. Гарантия 24 месяца. Доставка по России.', settings))
})

// Catalog page
app.get('/katalog', async (c) => {
  const settings = c.get('settings')
  const logoUrl = settings.logo_url || 'https://www.genspark.ai/api/files/s/eBVbsOpD'
  
  const content = `
  <header class="bg-white shadow-sm sticky top-0 z-50">
    <div class="max-w-7xl mx-auto">
      <nav class="flex items-center justify-between px-6 py-4">
        <a href="/" class="flex items-center gap-3">
          <img src="${logoUrl}" alt="USSIL" class="h-8 w-auto">
          <span class="text-lg font-bold text-neutral-800">USSIL</span>
        </a>
        <div class="hidden lg:flex items-center gap-1">
          <a href="/katalog" class="px-4 py-2 rounded-lg text-primary-600 bg-primary-50 font-medium">Каталог</a>
          <a href="/o-kompanii" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">О компании</a>
          <a href="/kejsy" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Кейсы</a>
          <a href="/dostavka" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Доставка</a>
          <a href="/kontakty" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Контакты</a>
        </div>
        <div class="flex items-center gap-4">
          <a href="tel:${(settings.phone_main || '84923225431').replace(/[^+\\d]/g, '')}" class="hidden md:flex items-center gap-2 text-primary-600 font-semibold">
            <i class="fas fa-phone"></i> ${settings.phone_main || '8 (49232) 2-54-31'}
          </a>
          <button onclick="toggleMobileMenu()" class="lg:hidden w-10 h-10 rounded-lg bg-neutral-100 flex items-center justify-center">
            <i class="fas fa-bars text-neutral-600"></i>
          </button>
        </div>
      </nav>
      <!-- Mobile Menu -->
      <div id="mobileMenu" class="hidden lg:hidden border-t border-neutral-100 bg-white">
        <div class="px-6 py-4 space-y-2">
          <a href="/katalog" class="block px-4 py-3 rounded-lg bg-primary-50 text-primary-600 font-medium">Каталог</a>
          <a href="/o-kompanii" class="block px-4 py-3 rounded-lg text-neutral-600 hover:bg-neutral-50 font-medium">О компании</a>
          <a href="/kejsy" class="block px-4 py-3 rounded-lg text-neutral-600 hover:bg-neutral-50 font-medium">Кейсы</a>
          <a href="/dostavka" class="block px-4 py-3 rounded-lg text-neutral-600 hover:bg-neutral-50 font-medium">Доставка</a>
          <a href="/kontakty" class="block px-4 py-3 rounded-lg text-neutral-600 hover:bg-neutral-50 font-medium">Контакты</a>
        </div>
      </div>
    </div>
  </header>

  <main class="py-8 lg:py-12">
    <div class="max-w-7xl mx-auto px-4 sm:px-6">
      <div class="mb-6 lg:mb-8">
        <h1 class="text-2xl lg:text-3xl font-bold text-neutral-800 mb-2">Каталог продукции</h1>
        <p class="text-neutral-600">Погрузочные рампы и эстакады от производителя</p>
      </div>
      
      <!-- Mobile categories filter button -->
      <button onclick="toggleCategoriesFilter()" class="lg:hidden w-full mb-4 px-4 py-3 bg-white rounded-xl shadow-sm border border-neutral-200 flex items-center justify-between">
        <span class="font-medium text-neutral-700"><i class="fas fa-filter mr-2"></i>Фильтр по категориям</span>
        <i class="fas fa-chevron-down text-neutral-400"></i>
      </button>
      
      <div class="flex flex-col lg:flex-row gap-6 lg:gap-8">
        <aside id="categoriesAside" class="hidden lg:block lg:w-64 flex-shrink-0">
          <div class="bg-white rounded-2xl p-6 shadow-sm lg:sticky lg:top-24">
            <h3 class="font-semibold text-neutral-800 mb-4">Категории</h3>
            <div id="filter-categories" class="space-y-2">
              <!-- Categories loaded via JS -->
            </div>
          </div>
        </aside>
        
        <div class="flex-1">
          <div id="product-grid" class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4 lg:gap-6">
            <!-- Products loaded via JS -->
          </div>
        </div>
      </div>
    </div>
  </main>

  <footer class="bg-neutral-800 text-white py-8 mt-12">
    <div class="max-w-7xl mx-auto px-6 text-center text-neutral-400 text-sm">
      &copy; ${new Date().getFullYear()} USSIL. Все права защищены.
    </div>
  </footer>
  
  <script>
    function toggleMobileMenu() {
      const menu = document.getElementById('mobileMenu');
      menu.classList.toggle('hidden');
    }
    function toggleCategoriesFilter() {
      const aside = document.getElementById('categoriesAside');
      aside.classList.toggle('hidden');
      aside.classList.toggle('mb-4');
    }
  </script>
  `
  
  return c.html(renderPage('Каталог продукции', content, 'Каталог рамп и эстакад | USSIL', 
    'Каталог погрузочных рамп и эстакад от производителя. Мобильные, гидравлические рампы, эстакады. Цены, характеристики.', settings))
})

// Category page
app.get('/katalog/:slug', async (c) => {
  const slug = c.req.param('slug')
  const settings = c.get('settings')
  const logoUrl = settings.logo_url || 'https://www.genspark.ai/api/files/s/eBVbsOpD'
  
  // Get category info
  let category: any = null
  try {
    const catResult = await c.env.DB.prepare('SELECT * FROM categories WHERE slug = ?').bind(slug).first()
    category = catResult
  } catch (e) {}
  
  if (!category) {
    return c.notFound()
  }
  
  const content = `
  ${getInnerPageHeader(settings, '/katalog')}

  <main class="py-8 lg:py-12">
    <div class="max-w-7xl mx-auto px-4 sm:px-6">
      <div class="mb-6 lg:mb-8">
        <nav class="text-sm text-neutral-500 mb-4">
          <a href="/" class="hover:text-primary-600">Главная</a> / 
          <a href="/katalog" class="hover:text-primary-600">Каталог</a> / 
          <span class="text-neutral-800">${category.name}</span>
        </nav>
        <h1 class="text-2xl lg:text-3xl font-bold text-neutral-800 mb-2">${category.name}</h1>
        <p class="text-neutral-600">${category.description || ''}</p>
      </div>
      
      <div id="product-grid" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
        <!-- Products loaded via JS -->
      </div>
    </div>
  </main>

  ${getInnerPageFooter(settings)}
  
  <script>
    function toggleMobileMenu() {
      const menu = document.getElementById('mobileMenu');
      menu.classList.toggle('hidden');
    }
    
    // Load products for this category
    async function loadProducts() {
      try {
        const response = await fetch('/api/products?category=${slug}');
        const data = await response.json();
        if (data.success && data.data) {
          const grid = document.getElementById('product-grid');
          if (data.data.length === 0) {
            grid.innerHTML = '<div class="col-span-full text-center py-12 text-neutral-500">В этой категории пока нет товаров</div>';
            return;
          }
          grid.innerHTML = data.data.map(p => {
            const priceWithVAT = p.price ? Math.round(p.price * 1.22) : null;
            return \`
            <a href="/product/\${p.slug}" class="group bg-white rounded-2xl shadow-sm hover:shadow-xl transition-all overflow-hidden border border-neutral-100">
              <div class="aspect-video overflow-hidden">
                <img src="\${p.main_image || 'https://images.unsplash.com/photo-1586528116311-ad8dd3c8310d?w=600&h=400&fit=crop'}" 
                     alt="\${p.name}" class="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300">
              </div>
              <div class="p-5">
                \${p.is_hit ? '<span class="inline-block px-3 py-1 bg-accent-100 text-accent-700 text-xs font-semibold rounded-full mb-3">Хит продаж</span>' : ''}
                <h3 class="text-lg font-semibold text-neutral-800 mb-2 group-hover:text-primary-600">\${p.name}</h3>
                <p class="text-neutral-600 text-sm mb-4 line-clamp-2">\${p.short_description || ''}</p>
                <div class="flex flex-col">
                  <span class="text-xl font-bold text-primary-600">\${priceWithVAT ? priceWithVAT.toLocaleString('ru-RU') + ' ₽' : 'По запросу'}</span>
                  <span class="text-xs text-neutral-400 mt-1">с НДС 22%</span>
                </div>
              </div>
            </a>
          \`}).join('');
        }
      } catch(e) { 
        console.error('Error loading products', e);
        document.getElementById('product-grid').innerHTML = '<div class="col-span-full text-center py-12 text-red-500">Ошибка загрузки товаров</div>';
      }
    }
    
    document.addEventListener('DOMContentLoaded', loadProducts);
  </script>
  `
  
  return c.html(renderPage(category.name, content, `${category.seo_title || category.name + ' | USSIL'}`, 
    category.seo_description || `${category.name} от производителя. Цены, характеристики, доставка по России.`, settings))
})

// Product page
app.get('/product/:slug', async (c) => {
  const slug = c.req.param('slug')
  const settings = c.get('settings')
  const logoUrl = settings.logo_url || 'https://www.genspark.ai/api/files/s/eBVbsOpD'
  const phoneMain = settings.phone_main || '8 (49232) 2-54-31'
  const phoneClean = phoneMain.replace(/[^+\d]/g, '')
  
  const content = `
  <header class="bg-white shadow-sm sticky top-0 z-50">
    <div class="max-w-7xl mx-auto">
      <nav class="flex items-center justify-between px-4 sm:px-6 py-4">
        <a href="/" class="flex items-center gap-2 sm:gap-3">
          <img src="${logoUrl}" alt="USSIL" class="h-8 w-auto">
          <span class="text-lg font-bold text-neutral-800">USSIL</span>
        </a>
        <div class="hidden lg:flex items-center gap-1">
          <a href="/katalog" class="px-4 py-2 rounded-lg text-primary-600 bg-primary-50 font-medium">Каталог</a>
          <a href="/o-kompanii" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">О компании</a>
          <a href="/kejsy" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Кейсы</a>
          <a href="/dostavka" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Доставка</a>
          <a href="/kontakty" class="px-4 py-2 rounded-lg text-neutral-600 hover:text-primary-600 hover:bg-primary-50 transition-all font-medium">Контакты</a>
        </div>
        <div class="flex items-center gap-2 sm:gap-4">
          <a href="tel:${phoneClean}" class="hidden md:flex items-center gap-2 text-primary-600 font-semibold text-sm">
            <i class="fas fa-phone"></i> ${phoneMain}
          </a>
          <button onclick="toggleMobileMenu()" class="lg:hidden w-10 h-10 rounded-lg bg-neutral-100 flex items-center justify-center">
            <i class="fas fa-bars text-neutral-600"></i>
          </button>
        </div>
      </nav>
      <!-- Mobile Menu -->
      <div id="mobileMenu" class="hidden lg:hidden border-t border-neutral-100 bg-white">
        <div class="px-4 sm:px-6 py-4 space-y-2">
          <a href="/katalog" class="block px-4 py-3 rounded-lg bg-primary-50 text-primary-600 font-medium">Каталог</a>
          <a href="/o-kompanii" class="block px-4 py-3 rounded-lg text-neutral-600 hover:bg-neutral-50 font-medium">О компании</a>
          <a href="/kejsy" class="block px-4 py-3 rounded-lg text-neutral-600 hover:bg-neutral-50 font-medium">Кейсы</a>
          <a href="/dostavka" class="block px-4 py-3 rounded-lg text-neutral-600 hover:bg-neutral-50 font-medium">Доставка</a>
          <a href="/kontakty" class="block px-4 py-3 rounded-lg text-neutral-600 hover:bg-neutral-50 font-medium">Контакты</a>
          <a href="tel:${phoneClean}" class="block px-4 py-3 rounded-lg bg-accent-500 text-white text-center font-semibold mt-4">
            <i class="fas fa-phone mr-2"></i>Позвонить
          </a>
        </div>
      </div>
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
    <div class="max-w-7xl mx-auto px-4 sm:px-6 text-center text-neutral-400 text-sm">
      &copy; ${new Date().getFullYear()} USSIL. Все права защищены.
    </div>
  </footer>
  
  <script>
    function toggleMobileMenu() {
      const menu = document.getElementById('mobileMenu');
      menu.classList.toggle('hidden');
    }
    
    // Load product details
    async function loadProductDetail() {
      const container = document.getElementById('product-detail');
      const slug = container.dataset.slug;
      
      try {
        const response = await fetch('/api/products/' + slug);
        const data = await response.json();
        
        if (!data.success || !data.data) {
          container.innerHTML = '<div class="text-center py-12"><h2 class="text-2xl font-bold text-red-500">Товар не найден</h2><a href="/katalog" class="mt-4 inline-block text-primary-600 hover:underline">← Вернуться в каталог</a></div>';
          return;
        }
        
        const product = data.data;
        
        // Parse specifications
        let specs = {};
        try {
          specs = product.specifications ? (typeof product.specifications === 'string' ? JSON.parse(product.specifications) : product.specifications) : {};
        } catch(e) { specs = {}; }
        
        // Calculate price with VAT 22%
        const priceWithVAT = product.price ? Math.round(product.price * 1.22) : null;
        const oldPriceWithVAT = product.old_price ? Math.round(product.old_price * 1.22) : null;
        
        // Build specifications HTML
        const specKeys = ['Общая длина', 'Грузоподъемность', 'Длина площадки', 'Длина подъема', 'Высота подъема', 'Рабочая ширина рампы', 'Транспортировочные колеса', 'Подъемное устройство'];
        let specsHtml = '';
        specKeys.forEach(key => {
          if (specs[key]) {
            specsHtml += '<div class="flex justify-between py-3 border-b border-neutral-100"><span class="text-neutral-600">' + key + '</span><span class="font-semibold text-neutral-800">' + specs[key] + '</span></div>';
          }
        });
        
        // Add any extra specs
        Object.keys(specs).forEach(key => {
          if (!specKeys.includes(key) && specs[key]) {
            specsHtml += '<div class="flex justify-between py-3 border-b border-neutral-100"><span class="text-neutral-600">' + key + '</span><span class="font-semibold text-neutral-800">' + specs[key] + '</span></div>';
          }
        });
        
        // Parse images
        let images = [];
        try {
          images = product.images ? (typeof product.images === 'string' ? JSON.parse(product.images) : product.images) : [];
        } catch(e) { images = []; }
        
        const mainImage = product.main_image || 'https://images.unsplash.com/photo-1586528116311-ad8dd3c8310d?w=800&h=600&fit=crop';
        
        container.innerHTML = \`
          <nav class="text-sm text-neutral-500 mb-6">
            <a href="/" class="hover:text-primary-600">Главная</a> / 
            <a href="/katalog" class="hover:text-primary-600">Каталог</a> / 
            <span class="text-neutral-800">\${product.name}</span>
          </nav>
          
          <div class="grid lg:grid-cols-2 gap-8 lg:gap-12">
            <!-- Product Images -->
            <div class="space-y-4">
              <div class="aspect-video rounded-2xl overflow-hidden bg-neutral-100">
                <img id="main-product-image" src="\${mainImage}" alt="\${product.name}" class="w-full h-full object-cover">
              </div>
              \${images.length > 0 ? \`
                <div class="grid grid-cols-4 gap-2">
                  <button onclick="changeMainImage('\${mainImage}')" class="aspect-video rounded-lg overflow-hidden border-2 border-primary-500">
                    <img src="\${mainImage}" alt="" class="w-full h-full object-cover">
                  </button>
                  \${images.slice(0, 3).map(img => \`
                    <button onclick="changeMainImage('\${img}')" class="aspect-video rounded-lg overflow-hidden border-2 border-transparent hover:border-primary-500 transition-colors">
                      <img src="\${img}" alt="" class="w-full h-full object-cover">
                    </button>
                  \`).join('')}
                </div>
              \` : ''}
            </div>
            
            <!-- Product Info -->
            <div class="space-y-6">
              <div>
                \${product.is_hit ? '<span class="inline-block px-3 py-1 bg-accent-100 text-accent-700 text-xs font-semibold rounded-full mb-3">Хит продаж</span>' : ''}
                \${product.is_new ? '<span class="inline-block px-3 py-1 bg-green-100 text-green-700 text-xs font-semibold rounded-full mb-3 ml-2">Новинка</span>' : ''}
                <h1 class="text-2xl lg:text-3xl font-bold text-neutral-800 mb-2">\${product.name}</h1>
                <p class="text-neutral-600">\${product.short_description || ''}</p>
              </div>
              
              <div class="bg-neutral-50 rounded-2xl p-6">
                <div class="flex items-baseline gap-4 mb-2">
                  \${priceWithVAT ? \`
                    <span class="text-3xl font-bold text-primary-600">\${priceWithVAT.toLocaleString('ru-RU')} ₽</span>
                    \${oldPriceWithVAT ? \`<span class="text-xl text-neutral-400 line-through">\${oldPriceWithVAT.toLocaleString('ru-RU')} ₽</span>\` : ''}
                  \` : '<span class="text-2xl font-bold text-primary-600">Цена по запросу</span>'}
                </div>
                <p class="text-sm text-neutral-500">Цена указана с НДС 22%</p>
                
                <div class="flex items-center gap-3 mt-4">
                  \${product.in_stock 
                    ? '<span class="flex items-center gap-2 text-green-600"><i class="fas fa-check-circle"></i> В наличии</span>'
                    : '<span class="flex items-center gap-2 text-orange-600"><i class="fas fa-clock"></i> Под заказ</span>'
                  }
                </div>
                
                <div class="flex flex-col sm:flex-row gap-3 mt-6">
                  <a href="#contact-form" class="flex-1 px-6 py-3 bg-primary-600 hover:bg-primary-700 text-white font-semibold rounded-xl text-center transition-colors">
                    <i class="fas fa-phone-alt mr-2"></i> Заказать звонок
                  </a>
                  <a href="https://wa.me/89209160100?text=\${encodeURIComponent('Здравствуйте! Интересует товар: ' + product.name)}" target="_blank" 
                     class="flex-1 px-6 py-3 bg-green-500 hover:bg-green-600 text-white font-semibold rounded-xl text-center transition-colors">
                    <i class="fab fa-whatsapp mr-2"></i> WhatsApp
                  </a>
                </div>
              </div>
              
              \${specsHtml ? \`
                <div class="bg-white border border-neutral-200 rounded-2xl p-6">
                  <h2 class="text-lg font-bold text-neutral-800 mb-4"><i class="fas fa-list-alt mr-2 text-primary-500"></i> Характеристики</h2>
                  <div class="divide-y divide-neutral-100">
                    \${specsHtml}
                  </div>
                </div>
              \` : ''}
              
              <div class="grid grid-cols-2 gap-4">
                <div class="bg-blue-50 rounded-xl p-4 text-center">
                  <i class="fas fa-shield-alt text-2xl text-blue-600 mb-2"></i>
                  <p class="text-sm font-semibold text-neutral-800">Гарантия 24 мес</p>
                </div>
                <div class="bg-green-50 rounded-xl p-4 text-center">
                  <i class="fas fa-truck text-2xl text-green-600 mb-2"></i>
                  <p class="text-sm font-semibold text-neutral-800">Доставка по РФ</p>
                </div>
              </div>
            </div>
          </div>
          
          \${product.full_description ? \`
            <div class="mt-12 bg-white border border-neutral-200 rounded-2xl p-6 lg:p-8">
              <h2 class="text-xl font-bold text-neutral-800 mb-4">Описание</h2>
              <div class="prose max-w-none text-neutral-600">\${product.full_description}</div>
            </div>
          \` : ''}
          
          <!-- Contact Form Section -->
          <section id="contact-form" class="mt-12 bg-gradient-to-br from-primary-600 to-primary-800 rounded-2xl p-6 lg:p-10">
            <div class="max-w-2xl mx-auto text-center text-white">
              <h2 class="text-2xl lg:text-3xl font-bold mb-4">Получить консультацию</h2>
              <p class="mb-6 text-primary-100">Оставьте заявку и наш менеджер свяжется с вами в ближайшее время</p>
              <form id="product-lead-form" class="space-y-4">
                <input type="hidden" name="product_id" value="\${product.id}">
                <input type="hidden" name="product_name" value="\${product.name}">
                <div class="grid sm:grid-cols-2 gap-4">
                  <input type="text" name="name" placeholder="Ваше имя" required class="w-full px-4 py-3 rounded-xl border-0 text-neutral-800 placeholder-neutral-400">
                  <input type="tel" name="phone" placeholder="Телефон" required class="w-full px-4 py-3 rounded-xl border-0 text-neutral-800 placeholder-neutral-400">
                </div>
                <textarea name="message" placeholder="Сообщение (необязательно)" rows="3" class="w-full px-4 py-3 rounded-xl border-0 text-neutral-800 placeholder-neutral-400"></textarea>
                <button type="submit" class="w-full sm:w-auto px-8 py-3 bg-accent-500 hover:bg-accent-600 text-white font-semibold rounded-xl transition-colors">
                  <i class="fas fa-paper-plane mr-2"></i> Отправить заявку
                </button>
              </form>
            </div>
          </section>
        \`;
        
        // Update page title
        document.title = product.name + ' | USSIL';
        
        // Handle form submission
        document.getElementById('product-lead-form').addEventListener('submit', async (e) => {
          e.preventDefault();
          const formData = new FormData(e.target);
          const data = {
            name: formData.get('name'),
            phone: formData.get('phone'),
            message: formData.get('message') + ' [Товар: ' + formData.get('product_name') + ']',
            source: 'product_page'
          };
          
          try {
            const response = await fetch('/api/leads', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(data)
            });
            
            if (response.ok) {
              alert('Спасибо! Ваша заявка отправлена. Мы свяжемся с вами в ближайшее время.');
              e.target.reset();
            } else {
              alert('Ошибка отправки. Позвоните нам по телефону.');
            }
          } catch (err) {
            alert('Ошибка отправки. Позвоните нам по телефону.');
          }
        });
        
      } catch(e) {
        console.error('Error loading product', e);
        container.innerHTML = '<div class="text-center py-12"><h2 class="text-2xl font-bold text-red-500">Ошибка загрузки товара</h2><a href="/katalog" class="mt-4 inline-block text-primary-600 hover:underline">← Вернуться в каталог</a></div>';
      }
    }
    
    function changeMainImage(src) {
      document.getElementById('main-product-image').src = src;
    }
    
    document.addEventListener('DOMContentLoaded', loadProductDetail);
  </script>
  `
  
  return c.html(renderPage('Товар', content, '', '', settings))
})

// Helper function for inner page header
const getInnerPageHeader = (settings: Record<string, string>, activePage: string) => {
  const logoUrl = settings.logo_url || 'https://www.genspark.ai/api/files/s/eBVbsOpD'
  const phoneMain = settings.phone_main || '8 (49232) 2-54-31'
  const phoneClean = phoneMain.replace(/[^+\\d]/g, '')
  
  const pages = [
    { href: '/katalog', name: 'Каталог' },
    { href: '/o-kompanii', name: 'О компании' },
    { href: '/kejsy', name: 'Кейсы' },
    { href: '/dostavka', name: 'Доставка' },
    { href: '/kontakty', name: 'Контакты' }
  ]
  
  return `
  <header class="bg-white shadow-sm sticky top-0 z-50">
    <div class="max-w-7xl mx-auto">
      <nav class="flex items-center justify-between px-4 sm:px-6 py-4">
        <a href="/" class="flex items-center gap-2 sm:gap-3">
          <img src="${logoUrl}" alt="USSIL" class="h-8 w-auto">
          <span class="text-lg font-bold text-neutral-800">USSIL</span>
        </a>
        <div class="hidden lg:flex items-center gap-1">
          ${pages.map(p => `<a href="${p.href}" class="px-4 py-2 rounded-lg ${activePage === p.href ? 'text-primary-600 bg-primary-50' : 'text-neutral-600 hover:text-primary-600 hover:bg-primary-50'} transition-all font-medium">${p.name}</a>`).join('')}
        </div>
        <div class="flex items-center gap-2 sm:gap-4">
          <a href="tel:${phoneClean}" class="hidden md:flex items-center gap-2 text-primary-600 font-semibold text-sm">
            <i class="fas fa-phone"></i> ${phoneMain}
          </a>
          <button onclick="toggleMobileMenu()" class="lg:hidden w-10 h-10 rounded-lg bg-neutral-100 flex items-center justify-center">
            <i class="fas fa-bars text-neutral-600"></i>
          </button>
        </div>
      </nav>
      <!-- Mobile Menu -->
      <div id="mobileMenu" class="hidden lg:hidden border-t border-neutral-100 bg-white">
        <div class="px-4 sm:px-6 py-4 space-y-2">
          ${pages.map(p => `<a href="${p.href}" class="block px-4 py-3 rounded-lg ${activePage === p.href ? 'bg-primary-50 text-primary-600' : 'text-neutral-600 hover:bg-neutral-50'} font-medium">${p.name}</a>`).join('')}
          <a href="tel:${phoneClean}" class="block px-4 py-3 rounded-lg bg-accent-500 text-white text-center font-semibold mt-4">
            <i class="fas fa-phone mr-2"></i>Позвонить
          </a>
        </div>
      </div>
    </div>
  </header>`
}

const getInnerPageFooter = () => `
  <footer class="bg-neutral-800 text-white py-8 mt-12">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 text-center text-neutral-400 text-sm">
      &copy; ${new Date().getFullYear()} USSIL. Все права защищены.
    </div>
  </footer>
  
  <script>
    function toggleMobileMenu() {
      const menu = document.getElementById('mobileMenu');
      menu.classList.toggle('hidden');
    }
  </script>`

// Static pages
app.get('/o-kompanii', async (c) => {
  const settings = c.get('settings')
  const content = `
  ${getInnerPageHeader(settings, '/o-kompanii')}

  <main class="py-8 lg:py-12">
    <div class="max-w-4xl mx-auto px-4 sm:px-6">
      <h1 class="text-2xl lg:text-3xl font-bold text-neutral-800 mb-6 lg:mb-8">О компании USSIL</h1>
      
      <div class="prose prose-lg max-w-none">
        <p class="text-neutral-600 text-base lg:text-lg leading-relaxed mb-6">
          Компания USSIL — один из ведущих российских производителей погрузочного оборудования. 
          С 2010 года мы разрабатываем и изготавливаем погрузочные рампы и эстакады для складов, 
          логистических центров и производственных предприятий.
        </p>
        
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 lg:gap-6 my-6 lg:my-8">
          <div class="p-5 lg:p-6 bg-primary-50 rounded-2xl">
            <h3 class="font-semibold text-primary-800 mb-2"><i class="fas fa-industry mr-2"></i>Собственное производство</h3>
            <p class="text-primary-700 text-sm">Полный цикл производства на собственных мощностях</p>
          </div>
          <div class="p-5 lg:p-6 bg-accent-50 rounded-2xl">
            <h3 class="font-semibold text-accent-800 mb-2"><i class="fas fa-certificate mr-2"></i>Сертификация</h3>
            <p class="text-accent-700 text-sm">Вся продукция сертифицирована и соответствует ГОСТ</p>
          </div>
          <div class="p-5 lg:p-6 bg-green-50 rounded-2xl">
            <h3 class="font-semibold text-green-800 mb-2"><i class="fas fa-shield-alt mr-2"></i>Гарантия</h3>
            <p class="text-green-700 text-sm">1 год гарантии при соблюдении условий эксплуатации</p>
          </div>
          <div class="p-5 lg:p-6 bg-blue-50 rounded-2xl">
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

  ${getInnerPageFooter()}
  `
  
  return c.html(renderPage('О компании', content, 'О компании USSIL — производитель рамп и эстакад', 
    'USSIL — российский производитель погрузочных рамп и эстакад с 2010 года. Собственное производство, гарантия качества.', settings))
})

app.get('/kontakty', async (c) => {
  const settings = c.get('settings')
  
  const content = `
  ${getInnerPageHeader(settings, '/kontakty')}

  <main class="py-8 lg:py-12">
    <div class="max-w-4xl mx-auto px-4 sm:px-6">
      <h1 class="text-2xl lg:text-3xl font-bold text-neutral-800 mb-6 lg:mb-8">Контакты</h1>
      
      <div class="grid md:grid-cols-2 gap-6 lg:gap-8">
        <div class="space-y-4 lg:space-y-6">
          <div class="p-5 lg:p-6 bg-white rounded-2xl shadow-sm">
            <div class="flex items-center gap-4">
              <div class="w-12 h-12 rounded-xl bg-primary-100 flex items-center justify-center flex-shrink-0">
                <i class="fas fa-phone text-xl text-primary-600"></i>
              </div>
              <div>
                <div class="text-sm text-neutral-500">Телефон</div>
                <a href="tel:${(settings.phone_main || '84923225431').replace(/[^+\\d]/g, '')}" class="text-lg font-semibold text-neutral-800">${settings.phone_main || '8 (49232) 2-54-31'}</a>
              </div>
            </div>
          </div>
          
          <div class="p-5 lg:p-6 bg-white rounded-2xl shadow-sm">
            <div class="flex items-center gap-4">
              <div class="w-12 h-12 rounded-xl bg-primary-100 flex items-center justify-center flex-shrink-0">
                <i class="fas fa-envelope text-xl text-primary-600"></i>
              </div>
              <div>
                <div class="text-sm text-neutral-500">Email</div>
                <a href="mailto:${settings.email || 'info@ussil.ru'}" class="text-lg font-semibold text-neutral-800">${settings.email || 'info@ussil.ru'}</a>
              </div>
            </div>
          </div>
          
          <div class="p-5 lg:p-6 bg-white rounded-2xl shadow-sm">
            <div class="flex items-center gap-4">
              <div class="w-12 h-12 rounded-xl bg-primary-100 flex items-center justify-center flex-shrink-0">
                <i class="fas fa-map-marker-alt text-xl text-primary-600"></i>
              </div>
              <div>
                <div class="text-sm text-neutral-500">Адрес</div>
                <div class="text-base lg:text-lg font-semibold text-neutral-800">${settings.address || 'г. Ковров, ул. Свердлова, 108А'}</div>
              </div>
            </div>
          </div>
          
          <div class="p-5 lg:p-6 bg-white rounded-2xl shadow-sm">
            <div class="flex items-center gap-4">
              <div class="w-12 h-12 rounded-xl bg-primary-100 flex items-center justify-center flex-shrink-0">
                <i class="fas fa-clock text-xl text-primary-600"></i>
              </div>
              <div>
                <div class="text-sm text-neutral-500">Режим работы</div>
                <div class="text-base lg:text-lg font-semibold text-neutral-800">${settings.working_hours || 'Пн-Пт: 9:00-18:00'}</div>
              </div>
            </div>
          </div>
        </div>
        
        <div class="bg-white rounded-2xl p-6 lg:p-8 shadow-sm">
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

  ${getInnerPageFooter()}
  `
  
  return c.html(renderPage('Контакты', content, 'Контакты | USSIL', 
    'Контакты компании USSIL. Телефон, email, адрес производства.', settings))
})

app.get('/dostavka', async (c) => {
  const settings = c.get('settings')
  
  const content = `
  ${getInnerPageHeader(settings, '/dostavka')}

  <main class="py-8 lg:py-12">
    <div class="max-w-4xl mx-auto px-4 sm:px-6">
      <h1 class="text-2xl lg:text-3xl font-bold text-neutral-800 mb-6 lg:mb-8">Доставка и оплата</h1>
      
      <div class="space-y-6 lg:space-y-8">
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
        
        <div class="bg-white rounded-2xl p-6 lg:p-8 shadow-sm">
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

  ${getInnerPageFooter()}
  `
  
  return c.html(renderPage('Доставка и оплата', content, 'Доставка и оплата | USSIL', 
    'Условия доставки погрузочных рамп и эстакад по России. Оплата с НДС.', settings))
})

// Cases page
app.get('/kejsy', async (c) => {
  const settings = c.get('settings')
  
  // Load cases
  let cases: any[] = []
  try {
    const casesResult = await c.env.DB.prepare('SELECT * FROM cases WHERE is_active = 1 ORDER BY sort_order').all()
    cases = casesResult.results || []
  } catch (e) {}
  
  const content = `
  ${getInnerPageHeader(settings, '/kejsy')}

  <main class="py-8 lg:py-12">
    <div class="max-w-7xl mx-auto px-4 sm:px-6">
      <div class="mb-6 lg:mb-8">
        <h1 class="text-2xl lg:text-4xl font-bold text-neutral-800 mb-2 lg:mb-4">Наши кейсы</h1>
        <p class="text-neutral-600 text-base lg:text-lg">Реализованные проекты для ведущих компаний России</p>
      </div>
      
      ${cases.length > 0 ? `
      <div class="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 lg:gap-8">
        ${cases.map((item: any) => `
        <div class="group bg-white rounded-xl lg:rounded-2xl overflow-hidden shadow-sm hover:shadow-xl transition-all border border-neutral-100">
          <div class="relative h-40 sm:h-48 lg:h-56 overflow-hidden">
            <img src="${item.main_image || 'https://images.unsplash.com/photo-1586528116311-ad8dd3c8310d?w=600&h=400&fit=crop'}" alt="${item.title}" class="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500">
            <div class="absolute inset-0 bg-gradient-to-t from-black/60 to-transparent"></div>
            ${item.client_name ? `<div class="absolute bottom-3 lg:bottom-4 left-3 lg:left-4 right-3 lg:right-4">
              <span class="px-2 lg:px-3 py-1 bg-white/90 backdrop-blur text-xs font-medium rounded-full text-neutral-700">${item.client_name}</span>
            </div>` : ''}
          </div>
          <div class="p-4 lg:p-6">
            <h3 class="text-lg lg:text-xl font-semibold text-neutral-800 mb-2">${item.title}</h3>
            <p class="text-neutral-600 text-sm lg:text-base mb-3 lg:mb-4 line-clamp-3">${item.description || ''}</p>
            ${item.result_text ? `<div class="p-3 lg:p-4 bg-green-50 rounded-lg lg:rounded-xl mb-3 lg:mb-4">
              <div class="text-xs font-medium text-green-700 mb-1">Результат</div>
              <div class="text-sm text-green-800">${item.result_text}</div>
            </div>` : ''}
            <div class="flex items-center justify-between text-xs lg:text-sm text-neutral-500">
              ${item.location ? `<span><i class="fas fa-map-marker-alt mr-1"></i>${item.location}</span>` : '<span></span>'}
              ${item.completion_date ? `<span><i class="fas fa-calendar mr-1"></i>${item.completion_date}</span>` : ''}
            </div>
          </div>
        </div>
        `).join('')}
      </div>
      ` : `
      <div class="text-center py-12 lg:py-16">
        <div class="w-16 lg:w-20 h-16 lg:h-20 mx-auto bg-neutral-100 rounded-full flex items-center justify-center mb-4 lg:mb-6">
          <i class="fas fa-briefcase text-2xl lg:text-3xl text-neutral-400"></i>
        </div>
        <h3 class="text-lg lg:text-xl font-semibold text-neutral-800 mb-2">Кейсы появятся здесь</h3>
        <p class="text-neutral-500 text-sm lg:text-base">Скоро мы добавим информацию о реализованных проектах</p>
      </div>
      `}
    </div>
  </main>

  ${getInnerPageFooter()}
  `
  
  return c.html(renderPage('Кейсы', content, 'Наши кейсы | USSIL', 
    'Реализованные проекты компании USSIL. Кейсы установки погрузочных рамп и эстакад для крупных компаний России.', settings))
})

// Admin login page
app.get('/admin/login', async (c) => {
  return c.html(`<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Вход | Админ-панель</title>
  <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.5.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-neutral-100 font-sans min-h-screen flex items-center justify-center p-4">
  <div class="w-full max-w-md">
    <div class="text-center mb-8">
      <div class="w-16 h-16 mx-auto rounded-2xl bg-gradient-to-br from-blue-500 to-blue-700 flex items-center justify-center mb-4 shadow-lg">
        <span class="text-3xl font-bold text-white">U</span>
      </div>
      <h1 class="text-2xl font-bold text-neutral-800">USSIL</h1>
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
        const payload = {
          username: formData.get('username'),
          password: formData.get('password')
        };
        console.log('Sending login request:', payload.username);
        
        const response = await fetch('/api/admin/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        
        console.log('Response status:', response.status);
        const data = await response.json();
        console.log('Response data:', data);
        
        if (data.success) {
          localStorage.setItem('adminToken', data.token);
          localStorage.setItem('adminUser', JSON.stringify(data.user));
          window.location.href = '/admin';
        } else {
          errorEl.textContent = data.error || 'Ошибка авторизации';
          errorEl.classList.remove('hidden');
        }
      } catch (err) {
        console.error('Login error:', err);
        errorEl.textContent = 'Ошибка сети: ' + err.message;
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

// Admin panel - Full CMS
app.get('/admin', async (c) => {
  // Load categories for product form
  let categories: any[] = []
  try {
    const result = await c.env.DB.prepare('SELECT * FROM categories ORDER BY sort_order').all()
    categories = result.results || []
  } catch (e) {}
  
  const categoriesJson = JSON.stringify(categories)
  
  return c.html(`<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Админ-панель | USSIL CMS</title>
  <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.5.0/css/all.min.css" rel="stylesheet">
  <style>
    .modal { display: none; }
    .modal.active { display: flex; }
    .tab-btn.active { background: #3b82f6; color: white; }
    .image-preview { width: 100px; height: 100px; object-fit: cover; border-radius: 8px; }
  </style>
</head>
<body class="bg-neutral-50 font-sans">
  <script>
    if (!localStorage.getItem('adminToken')) {
      window.location.href = '/admin/login';
    }
    const categories = ${categoriesJson};
  </script>
  
  <div class="min-h-screen flex">
    <!-- Sidebar -->
    <aside class="w-64 bg-white border-r border-neutral-200 flex flex-col fixed h-full">
      <div class="p-6 border-b border-neutral-100">
        <h1 class="text-xl font-bold text-neutral-800">USSIL</h1>
        <p class="text-neutral-500 text-sm">Система управления</p>
      </div>
      <nav class="p-4 space-y-1 flex-1 overflow-y-auto">
        <a href="#dashboard" onclick="showSection('dashboard')" class="nav-link flex items-center gap-3 px-4 py-3 rounded-xl bg-blue-50 text-blue-600 font-medium">
          <i class="fas fa-chart-pie w-5"></i> Дашборд
        </a>
        <a href="#products" onclick="showSection('products')" class="nav-link flex items-center gap-3 px-4 py-3 rounded-xl text-neutral-600 hover:bg-neutral-50 transition-colors">
          <i class="fas fa-boxes w-5"></i> Товары
        </a>
        <a href="#categories" onclick="showSection('categories')" class="nav-link flex items-center gap-3 px-4 py-3 rounded-xl text-neutral-600 hover:bg-neutral-50 transition-colors">
          <i class="fas fa-folder w-5"></i> Категории
        </a>
        <a href="#cases" onclick="showSection('cases')" class="nav-link flex items-center gap-3 px-4 py-3 rounded-xl text-neutral-600 hover:bg-neutral-50 transition-colors">
          <i class="fas fa-briefcase w-5"></i> Кейсы
        </a>
        <a href="#partners" onclick="showSection('partners')" class="nav-link flex items-center gap-3 px-4 py-3 rounded-xl text-neutral-600 hover:bg-neutral-50 transition-colors">
          <i class="fas fa-handshake w-5"></i> Партнёры
        </a>
        <a href="#leads" onclick="showSection('leads')" class="nav-link flex items-center gap-3 px-4 py-3 rounded-xl text-neutral-600 hover:bg-neutral-50 transition-colors">
          <i class="fas fa-envelope w-5"></i> Заявки
        </a>
        <a href="#settings" onclick="showSection('settings')" class="nav-link flex items-center gap-3 px-4 py-3 rounded-xl text-neutral-600 hover:bg-neutral-50 transition-colors">
          <i class="fas fa-cog w-5"></i> Настройки сайта
        </a>
      </nav>
      <div class="p-4 border-t border-neutral-100">
        <div class="text-sm text-neutral-500 mb-2">Вошли как: <strong id="admin-name">Администратор</strong></div>
        <button onclick="logout()" class="w-full px-4 py-2 rounded-xl border border-neutral-200 text-neutral-600 hover:bg-neutral-50 transition-colors text-sm">
          <i class="fas fa-sign-out-alt mr-2"></i> Выйти
        </button>
      </div>
    </aside>

    <!-- Main Content -->
    <main class="flex-1 ml-64 p-8">
      <!-- Dashboard -->
      <section id="section-dashboard" class="admin-section">
        <h2 class="text-2xl font-bold text-neutral-800 mb-6">Дашборд</h2>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div class="p-6 bg-white rounded-2xl shadow-sm border border-neutral-100">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-neutral-500 text-sm mb-1">Товаров</p>
                <p id="stat-products" class="text-3xl font-bold text-blue-600">0</p>
              </div>
              <div class="w-12 h-12 bg-blue-100 rounded-xl flex items-center justify-center">
                <i class="fas fa-boxes text-blue-600"></i>
              </div>
            </div>
          </div>
          <div class="p-6 bg-white rounded-2xl shadow-sm border border-neutral-100">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-neutral-500 text-sm mb-1">Всего заявок</p>
                <p id="stat-leads" class="text-3xl font-bold text-green-600">0</p>
              </div>
              <div class="w-12 h-12 bg-green-100 rounded-xl flex items-center justify-center">
                <i class="fas fa-envelope text-green-600"></i>
              </div>
            </div>
          </div>
          <div class="p-6 bg-white rounded-2xl shadow-sm border border-neutral-100">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-neutral-500 text-sm mb-1">Новых заявок</p>
                <p id="stat-new-leads" class="text-3xl font-bold text-orange-500">0</p>
              </div>
              <div class="w-12 h-12 bg-orange-100 rounded-xl flex items-center justify-center">
                <i class="fas fa-bell text-orange-500"></i>
              </div>
            </div>
          </div>
          <div class="p-6 bg-white rounded-2xl shadow-sm border border-neutral-100">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-neutral-500 text-sm mb-1">Просмотров</p>
                <p id="stat-views" class="text-3xl font-bold text-purple-600">0</p>
              </div>
              <div class="w-12 h-12 bg-purple-100 rounded-xl flex items-center justify-center">
                <i class="fas fa-eye text-purple-600"></i>
              </div>
            </div>
          </div>
        </div>
        <div class="bg-white rounded-2xl p-6 shadow-sm border border-neutral-100">
          <h3 class="font-semibold text-neutral-800 mb-4">Последние заявки</h3>
          <div id="recent-leads" class="space-y-3"></div>
        </div>
      </section>

      <!-- Products Section -->
      <section id="section-products" class="admin-section hidden">
        <div class="flex justify-between items-center mb-6">
          <h2 class="text-2xl font-bold text-neutral-800">Управление товарами</h2>
          <button onclick="openProductModal()" class="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-xl transition-colors flex items-center gap-2">
            <i class="fas fa-plus"></i> Добавить товар
          </button>
        </div>
        <div class="bg-white rounded-2xl shadow-sm border border-neutral-100 overflow-hidden">
          <table class="w-full">
            <thead class="bg-neutral-50 border-b border-neutral-100">
              <tr>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Фото</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Товар</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Категория</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Цена</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Статус</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Действия</th>
              </tr>
            </thead>
            <tbody id="products-table" class="divide-y divide-neutral-100"></tbody>
          </table>
        </div>
      </section>

      <!-- Categories Section -->
      <section id="section-categories" class="admin-section hidden">
        <div class="flex justify-between items-center mb-6">
          <h2 class="text-2xl font-bold text-neutral-800">Категории</h2>
          <button onclick="openCategoryModal()" class="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-xl transition-colors flex items-center gap-2">
            <i class="fas fa-plus"></i> Добавить категорию
          </button>
        </div>
        <div class="bg-white rounded-2xl shadow-sm border border-neutral-100 overflow-hidden">
          <table class="w-full">
            <thead class="bg-neutral-50 border-b border-neutral-100">
              <tr>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Название</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Slug</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Порядок</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Статус</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Действия</th>
              </tr>
            </thead>
            <tbody id="categories-table" class="divide-y divide-neutral-100"></tbody>
          </table>
        </div>
      </section>

      <!-- Cases Section -->
      <section id="section-cases" class="admin-section hidden">
        <div class="flex justify-between items-center mb-6">
          <h2 class="text-2xl font-bold text-neutral-800">Кейсы</h2>
          <button onclick="openCaseModal()" class="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-xl transition-colors flex items-center gap-2">
            <i class="fas fa-plus"></i> Добавить кейс
          </button>
        </div>
        <div class="bg-white rounded-2xl shadow-sm border border-neutral-100 overflow-hidden">
          <table class="w-full">
            <thead class="bg-neutral-50 border-b border-neutral-100">
              <tr>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Фото</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Название</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Клиент</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Локация</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Статус</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Действия</th>
              </tr>
            </thead>
            <tbody id="cases-table" class="divide-y divide-neutral-100"></tbody>
          </table>
        </div>
      </section>

      <!-- Partners Section -->
      <section id="section-partners" class="admin-section hidden">
        <div class="flex justify-between items-center mb-6">
          <h2 class="text-2xl font-bold text-neutral-800">Партнёры</h2>
          <button onclick="openPartnerModal()" class="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-xl transition-colors flex items-center gap-2">
            <i class="fas fa-plus"></i> Добавить партнёра
          </button>
        </div>
        <div class="bg-white rounded-2xl shadow-sm border border-neutral-100 overflow-hidden">
          <table class="w-full">
            <thead class="bg-neutral-50 border-b border-neutral-100">
              <tr>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Логотип</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Название</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Сайт</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Порядок</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Статус</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Действия</th>
              </tr>
            </thead>
            <tbody id="partners-table" class="divide-y divide-neutral-100"></tbody>
          </table>
        </div>
      </section>

      <!-- Leads Section -->
      <section id="section-leads" class="admin-section hidden">
        <h2 class="text-2xl font-bold text-neutral-800 mb-6">Заявки</h2>
        <div class="bg-white rounded-2xl shadow-sm border border-neutral-100 overflow-hidden">
          <table class="w-full">
            <thead class="bg-neutral-50 border-b border-neutral-100">
              <tr>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Дата</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Имя</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Телефон</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Email</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Сообщение</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Статус</th>
                <th class="px-6 py-4 text-left text-sm text-neutral-500 font-medium">Действия</th>
              </tr>
            </thead>
            <tbody id="leads-table" class="divide-y divide-neutral-100"></tbody>
          </table>
        </div>
      </section>

      <!-- Settings Section -->
      <section id="section-settings" class="admin-section hidden">
        <h2 class="text-2xl font-bold text-neutral-800 mb-6">Настройки сайта</h2>
        
        <!-- Settings Tabs -->
        <div class="flex gap-2 mb-6">
          <button onclick="showSettingsTab('general')" class="tab-btn active px-4 py-2 rounded-lg text-sm font-medium transition-colors">Основные</button>
          <button onclick="showSettingsTab('contacts')" class="tab-btn px-4 py-2 rounded-lg text-sm font-medium bg-neutral-100 text-neutral-600 transition-colors">Контакты</button>
          <button onclick="showSettingsTab('hero')" class="tab-btn px-4 py-2 rounded-lg text-sm font-medium bg-neutral-100 text-neutral-600 transition-colors">Главная секция</button>
          <button onclick="showSettingsTab('blocks')" class="tab-btn px-4 py-2 rounded-lg text-sm font-medium bg-neutral-100 text-neutral-600 transition-colors">Блоки на сайте</button>
          <button onclick="showSettingsTab('about')" class="tab-btn px-4 py-2 rounded-lg text-sm font-medium bg-neutral-100 text-neutral-600 transition-colors">О компании</button>
          <button onclick="showSettingsTab('delivery')" class="tab-btn px-4 py-2 rounded-lg text-sm font-medium bg-neutral-100 text-neutral-600 transition-colors">Доставка</button>
          <button onclick="showSettingsTab('seo')" class="tab-btn px-4 py-2 rounded-lg text-sm font-medium bg-neutral-100 text-neutral-600 transition-colors">SEO</button>
          <button onclick="showSettingsTab('email')" class="tab-btn px-4 py-2 rounded-lg text-sm font-medium bg-neutral-100 text-neutral-600 transition-colors">Email-уведомления</button>
        </div>

        <form id="settings-form" class="space-y-6">
          <!-- General Settings -->
          <div id="settings-general" class="settings-tab bg-white rounded-2xl p-6 shadow-sm border border-neutral-100">
            <h3 class="text-lg font-semibold text-neutral-800 mb-4">Основные настройки</h3>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Название сайта</label>
                <input type="text" name="site_name" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200">
              </div>
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Слоган</label>
                <input type="text" name="site_tagline" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200">
              </div>
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Логотип сайта</label>
                <input type="text" name="logo_url" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="https://...">
                <div class="mt-2 flex items-center gap-4">
                  <input type="file" accept="image/*" onchange="uploadSettingsImage(this, 'logo_url')" class="text-sm text-neutral-500 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-medium file:bg-blue-50 file:text-blue-600 hover:file:bg-blue-100">
                  <span class="text-xs text-neutral-500">или вставьте URL</span>
                </div>
                <div id="logo_url_preview" class="mt-2 hidden">
                  <img src="" alt="Logo Preview" class="h-12 w-auto">
                </div>
              </div>
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Favicon URL</label>
                <input type="text" name="favicon_url" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="https://...">
              </div>
            </div>
          </div>

          <!-- Contact Settings -->
          <div id="settings-contacts" class="settings-tab hidden bg-white rounded-2xl p-6 shadow-sm border border-neutral-100">
            <h3 class="text-lg font-semibold text-neutral-800 mb-4">Контактная информация</h3>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Основной телефон</label>
                <input type="text" name="phone_main" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="+7 (800) 600-00-93">
              </div>
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">WhatsApp</label>
                <input type="text" name="phone_whatsapp" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="+79001234567">
              </div>
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Email для связи</label>
                <input type="email" name="email" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="info@company.ru">
              </div>
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Telegram</label>
                <input type="text" name="telegram" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="@username">
              </div>
              <div class="md:col-span-2">
                <label class="block text-sm font-medium text-neutral-700 mb-2">Адрес</label>
                <input type="text" name="address" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="г. Ковров, ул. Свердлова, 108А">
              </div>
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Время работы</label>
                <input type="text" name="working_hours" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="Пн-Пт: 9:00-18:00">
              </div>
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Карта (iframe или URL)</label>
                <input type="text" name="map_embed" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="https://yandex.ru/map-widget/...">
              </div>
            </div>
          </div>

          <!-- Hero Section Settings -->
          <div id="settings-hero" class="settings-tab hidden bg-white rounded-2xl p-6 shadow-sm border border-neutral-100">
            <h3 class="text-lg font-semibold text-neutral-800 mb-4">Главная секция (Hero)</h3>
            <div class="space-y-6">
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Заголовок</label>
                <input type="text" name="hero_title" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="Погрузочные рампы и эстакады">
              </div>
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Подзаголовок (выделенный текст)</label>
                <input type="text" name="hero_subtitle" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="от производителя">
              </div>
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Описание</label>
                <textarea name="hero_description" rows="3" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="Собственное производство во Владимире..."></textarea>
              </div>
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Фоновое изображение Hero-секции</label>
                <input type="text" name="hero_bg_image" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="https://...">
                <div class="mt-2 flex items-center gap-4">
                  <input type="file" accept="image/*" onchange="uploadSettingsImage(this, 'hero_bg_image')" class="text-sm text-neutral-500 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-medium file:bg-blue-50 file:text-blue-600 hover:file:bg-blue-100">
                  <span class="text-xs text-neutral-500">или вставьте URL</span>
                </div>
                <div id="hero_bg_image_preview" class="mt-2 hidden">
                  <img src="" alt="Preview" class="w-full max-w-md h-32 object-cover rounded-lg">
                </div>
              </div>
              <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div>
                  <label class="block text-sm font-medium text-neutral-700 mb-2">Статистика 1 (число)</label>
                  <input type="text" name="hero_stat1_value" class="w-full px-4 py-3 rounded-xl border border-neutral-200" placeholder="500+">
                </div>
                <div>
                  <label class="block text-sm font-medium text-neutral-700 mb-2">Статистика 1 (текст)</label>
                  <input type="text" name="hero_stat1_label" class="w-full px-4 py-3 rounded-xl border border-neutral-200" placeholder="Проектов">
                </div>
                <div>
                  <label class="block text-sm font-medium text-neutral-700 mb-2">Статистика 2 (число)</label>
                  <input type="text" name="hero_stat2_value" class="w-full px-4 py-3 rounded-xl border border-neutral-200" placeholder="12 лет">
                </div>
                <div>
                  <label class="block text-sm font-medium text-neutral-700 mb-2">Статистика 2 (текст)</label>
                  <input type="text" name="hero_stat2_label" class="w-full px-4 py-3 rounded-xl border border-neutral-200" placeholder="На рынке">
                </div>
              </div>
            </div>
          </div>

          <!-- Blocks Settings -->
          <div id="settings-blocks" class="settings-tab hidden bg-white rounded-2xl p-6 shadow-sm border border-neutral-100">
            <h3 class="text-lg font-semibold text-neutral-800 mb-4">Управление блоками на сайте</h3>
            <p class="text-neutral-600 text-sm mb-6">Включите или отключите отображение блоков на главной странице</p>
            <div class="space-y-4">
              <div class="flex items-center justify-between p-4 bg-neutral-50 rounded-xl">
                <div>
                  <div class="font-medium text-neutral-800">Категории продукции</div>
                  <div class="text-sm text-neutral-500">Секция с категориями товаров</div>
                </div>
                <label class="relative inline-flex items-center cursor-pointer">
                  <input type="checkbox" name="block_categories" class="sr-only peer" checked>
                  <div class="w-11 h-6 bg-neutral-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-100 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-neutral-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                </label>
              </div>
              <div class="flex items-center justify-between p-4 bg-neutral-50 rounded-xl">
                <div>
                  <div class="font-medium text-neutral-800">Популярные товары</div>
                  <div class="text-sm text-neutral-500">Секция с избранными товарами</div>
                </div>
                <label class="relative inline-flex items-center cursor-pointer">
                  <input type="checkbox" name="block_products" class="sr-only peer" checked>
                  <div class="w-11 h-6 bg-neutral-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-100 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-neutral-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                </label>
              </div>
              <div class="flex items-center justify-between p-4 bg-neutral-50 rounded-xl">
                <div>
                  <div class="font-medium text-neutral-800">Преимущества</div>
                  <div class="text-sm text-neutral-500">Секция "Почему выбирают нас"</div>
                </div>
                <label class="relative inline-flex items-center cursor-pointer">
                  <input type="checkbox" name="block_advantages" class="sr-only peer" checked>
                  <div class="w-11 h-6 bg-neutral-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-100 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-neutral-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                </label>
              </div>
              <div class="flex items-center justify-between p-4 bg-neutral-50 rounded-xl">
                <div>
                  <div class="font-medium text-neutral-800">Отзывы клиентов</div>
                  <div class="text-sm text-neutral-500">Секция с отзывами</div>
                </div>
                <label class="relative inline-flex items-center cursor-pointer">
                  <input type="checkbox" name="block_reviews" class="sr-only peer" checked>
                  <div class="w-11 h-6 bg-neutral-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-100 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-neutral-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                </label>
              </div>
              <div class="flex items-center justify-between p-4 bg-neutral-50 rounded-xl">
                <div>
                  <div class="font-medium text-neutral-800">Форма заявки</div>
                  <div class="text-sm text-neutral-500">Секция "Получите расчет стоимости"</div>
                </div>
                <label class="relative inline-flex items-center cursor-pointer">
                  <input type="checkbox" name="block_contact_form" class="sr-only peer" checked>
                  <div class="w-11 h-6 bg-neutral-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-100 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-neutral-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                </label>
              </div>
              <div class="flex items-center justify-between p-4 bg-neutral-50 rounded-xl">
                <div>
                  <div class="font-medium text-neutral-800">Кейсы на главной</div>
                  <div class="text-sm text-neutral-500">Секция с реализованными проектами</div>
                </div>
                <label class="relative inline-flex items-center cursor-pointer">
                  <input type="checkbox" name="block_cases" class="sr-only peer" checked>
                  <div class="w-11 h-6 bg-neutral-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-100 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-neutral-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                </label>
              </div>
              <div class="flex items-center justify-between p-4 bg-neutral-50 rounded-xl">
                <div>
                  <div class="font-medium text-neutral-800">Кнопка WhatsApp</div>
                  <div class="text-sm text-neutral-500">Плавающая кнопка в углу экрана</div>
                </div>
                <label class="relative inline-flex items-center cursor-pointer">
                  <input type="checkbox" name="block_whatsapp" class="sr-only peer" checked>
                  <div class="w-11 h-6 bg-neutral-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-100 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-neutral-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                </label>
              </div>
            </div>
          </div>

          <!-- About Section Settings -->
          <div id="settings-about" class="settings-tab hidden bg-white rounded-2xl p-6 shadow-sm border border-neutral-100">
            <h3 class="text-lg font-semibold text-neutral-800 mb-4">Страница О компании</h3>
            <div class="space-y-6">
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Заголовок страницы</label>
                <input type="text" name="about_title" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="О компании USSIL">
              </div>
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Основной текст</label>
                <textarea name="about_content" rows="6" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="Описание компании..."></textarea>
              </div>
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Изображение компании</label>
                <input type="text" name="about_image" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="https://...">
                <div class="mt-2 flex items-center gap-4">
                  <input type="file" accept="image/*" onchange="uploadSettingsImage(this, 'about_image')" class="text-sm text-neutral-500 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-medium file:bg-blue-50 file:text-blue-600 hover:file:bg-blue-100">
                  <span class="text-xs text-neutral-500">или вставьте URL</span>
                </div>
                <div id="about_image_preview" class="mt-2 hidden">
                  <img src="" alt="Preview" class="w-48 h-32 object-cover rounded-lg">
                </div>
              </div>
              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="block text-sm font-medium text-neutral-700 mb-2">Срок гарантии</label>
                  <input type="text" name="guarantee_years" class="w-full px-4 py-3 rounded-xl border border-neutral-200" placeholder="1 год">
                </div>
                <div>
                  <label class="block text-sm font-medium text-neutral-700 mb-2">Опыт работы</label>
                  <input type="text" name="experience_years" class="w-full px-4 py-3 rounded-xl border border-neutral-200" placeholder="12 лет">
                </div>
              </div>
            </div>
          </div>

          <!-- Delivery Settings -->
          <div id="settings-delivery" class="settings-tab hidden bg-white rounded-2xl p-6 shadow-sm border border-neutral-100">
            <h3 class="text-lg font-semibold text-neutral-800 mb-4">Страница Доставка и оплата</h3>
            <div class="space-y-6">
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Заголовок страницы</label>
                <input type="text" name="delivery_title" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="Доставка и оплата">
              </div>
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Информация о доставке</label>
                <textarea name="delivery_content" rows="5" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="Доставка осуществляется..."></textarea>
              </div>
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Информация об оплате</label>
                <textarea name="payment_content" rows="5" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="Способы оплаты..."></textarea>
              </div>
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Регионы доставки</label>
                <textarea name="delivery_regions" rows="3" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="Владимир, Москва, Нижний Новгород..."></textarea>
              </div>
            </div>
          </div>

          <!-- SEO Settings -->
          <div id="settings-seo" class="settings-tab hidden bg-white rounded-2xl p-6 shadow-sm border border-neutral-100">
            <h3 class="text-lg font-semibold text-neutral-800 mb-4">SEO и аналитика</h3>
            <div class="space-y-6">
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Meta Title (главная)</label>
                <input type="text" name="seo_title" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="Погрузочные рампы и эстакады от производителя | USSIL">
              </div>
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Meta Description (главная)</label>
                <textarea name="seo_description" rows="3" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="Производитель погрузочных рамп..."></textarea>
              </div>
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Meta Keywords</label>
                <input type="text" name="seo_keywords" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="рампы, эстакады, погрузочное оборудование">
              </div>
              <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label class="block text-sm font-medium text-neutral-700 mb-2">Яндекс.Метрика ID</label>
                  <input type="text" name="yandex_metrika_id" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="12345678">
                </div>
                <div>
                  <label class="block text-sm font-medium text-neutral-700 mb-2">Google Analytics ID</label>
                  <input type="text" name="google_analytics_id" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="G-XXXXXXXXXX">
                </div>
              </div>
            </div>
          </div>

          <!-- Email Notifications Settings -->
          <div id="settings-email" class="settings-tab hidden bg-white rounded-2xl p-6 shadow-sm border border-neutral-100">
            <h3 class="text-lg font-semibold text-neutral-800 mb-4">Email-уведомления о заявках</h3>
            <div class="bg-blue-50 border border-blue-200 rounded-xl p-4 mb-6">
              <p class="text-sm text-blue-800"><i class="fas fa-info-circle mr-2"></i>При поступлении новой заявки уведомление будет отправлено на указанный email.</p>
            </div>
            <div class="space-y-6">
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Email для получения заявок</label>
                <input type="email" name="admin_email" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="admin@company.ru">
                <p class="text-xs text-neutral-500 mt-1">На этот адрес будут приходить уведомления о новых заявках</p>
              </div>
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Копия на дополнительный email</label>
                <input type="email" name="admin_email_cc" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="manager@company.ru">
                <p class="text-xs text-neutral-500 mt-1">Дополнительный получатель (необязательно)</p>
              </div>
              <div>
                <label class="block text-sm font-medium text-neutral-700 mb-2">Тема письма</label>
                <input type="text" name="email_subject_template" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="Новая заявка с сайта USSIL">
              </div>
            </div>
            
            <h3 class="text-lg font-semibold text-neutral-800 mt-8 mb-4"><i class="fab fa-telegram text-blue-500 mr-2"></i>Telegram-уведомления</h3>
            <div class="bg-green-50 border border-green-200 rounded-xl p-4 mb-6">
              <p class="text-sm text-green-800"><i class="fas fa-info-circle mr-2"></i>Получайте мгновенные уведомления о заявках в Telegram!</p>
              <p class="text-xs text-green-700 mt-2">Настройте через Cloudflare: TELEGRAM_BOT_TOKEN и TELEGRAM_CHAT_ID</p>
            </div>
            <div class="space-y-4">
              <div class="p-4 bg-neutral-50 rounded-xl">
                <p class="text-sm text-neutral-700 mb-2"><strong>Как настроить:</strong></p>
                <ol class="list-decimal list-inside text-sm text-neutral-600 space-y-1">
                  <li>Создайте бота через @BotFather и получите токен</li>
                  <li>Узнайте свой Chat ID через @userinfobot</li>
                  <li>Добавьте переменные в Cloudflare Pages → Settings → Environment variables</li>
                </ol>
              </div>
            </div>
          </div>

          <div class="flex gap-4">
            <button type="submit" class="px-8 py-3 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-xl transition-colors flex items-center gap-2">
              <i class="fas fa-save"></i> Сохранить все настройки
            </button>
          </div>
        </form>
      </section>
    </main>
  </div>

  <!-- Product Modal -->
  <div id="productModal" class="modal fixed inset-0 bg-black/50 z-50 items-center justify-center p-4">
    <div class="bg-white rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
      <div class="p-6 border-b border-neutral-100 flex justify-between items-center sticky top-0 bg-white">
        <h3 id="productModalTitle" class="text-xl font-bold text-neutral-800">Добавить товар</h3>
        <button onclick="closeProductModal()" class="w-10 h-10 rounded-xl hover:bg-neutral-100 transition-colors">
          <i class="fas fa-times text-neutral-500"></i>
        </button>
      </div>
      <form id="productForm" class="p-6 space-y-6">
        <input type="hidden" name="id" id="productId">
        
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label class="block text-sm font-medium text-neutral-700 mb-2">Название товара *</label>
            <input type="text" name="name" required class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200">
          </div>
          <div>
            <label class="block text-sm font-medium text-neutral-700 mb-2">Slug (URL) *</label>
            <input type="text" name="slug" required class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="rampa-t-9-7">
          </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label class="block text-sm font-medium text-neutral-700 mb-2">Категория *</label>
            <select name="category_id" required class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" id="productCategorySelect">
              <option value="">Выберите категорию</option>
            </select>
          </div>
          <div>
            <label class="block text-sm font-medium text-neutral-700 mb-2">Цена (₽) *</label>
            <input type="number" name="price" required class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="449000">
          </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label class="block text-sm font-medium text-neutral-700 mb-2">Старая цена (для скидки)</label>
            <input type="number" name="old_price" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="499000">
          </div>
          <div>
            <label class="block text-sm font-medium text-neutral-700 mb-2">Порядок сортировки</label>
            <input type="number" name="sort_order" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="0">
          </div>
        </div>

        <div>
          <label class="block text-sm font-medium text-neutral-700 mb-2">Краткое описание</label>
          <textarea name="short_description" rows="2" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="Краткое описание для карточки"></textarea>
        </div>

        <div>
          <label class="block text-sm font-medium text-neutral-700 mb-2">Полное описание</label>
          <textarea name="full_description" rows="4" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="Подробное описание товара"></textarea>
        </div>

        <div>
          <label class="block text-sm font-medium text-neutral-700 mb-2">Главное изображение</label>
          <input type="text" name="main_image" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="https://...">
          <div class="mt-2 flex items-center gap-4">
            <input type="file" accept="image/*" onchange="uploadImage(this, 'productForm', 'main_image')" class="text-sm text-neutral-500 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-medium file:bg-blue-50 file:text-blue-600 hover:file:bg-blue-100">
            <span class="text-xs text-neutral-500">или вставьте URL</span>
          </div>
          <div id="mainImagePreview" class="mt-2 hidden">
            <img src="" alt="Preview" class="image-preview">
          </div>
        </div>

        <div>
          <label class="block text-sm font-medium text-neutral-700 mb-2">Дополнительные изображения (URL, по одному на строку)</label>
          <textarea name="images" rows="3" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200" placeholder="https://example.com/image1.jpg&#10;https://example.com/image2.jpg"></textarea>
        </div>

        <div>
          <label class="block text-sm font-medium text-neutral-700 mb-3">Характеристики</label>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4 p-4 bg-neutral-50 rounded-xl">
            <div>
              <label class="block text-xs font-medium text-neutral-600 mb-1">Общая длина</label>
              <input type="text" name="spec_length" class="w-full px-3 py-2 rounded-lg border border-neutral-200 text-sm" placeholder="9 м">
            </div>
            <div>
              <label class="block text-xs font-medium text-neutral-600 mb-1">Грузоподъемность</label>
              <input type="text" name="spec_capacity" class="w-full px-3 py-2 rounded-lg border border-neutral-200 text-sm" placeholder="7 тонн">
            </div>
            <div>
              <label class="block text-xs font-medium text-neutral-600 mb-1">Длина площадки</label>
              <input type="text" name="spec_platform_length" class="w-full px-3 py-2 rounded-lg border border-neutral-200 text-sm" placeholder="3 м">
            </div>
            <div>
              <label class="block text-xs font-medium text-neutral-600 mb-1">Длина подъема</label>
              <input type="text" name="spec_lift_length" class="w-full px-3 py-2 rounded-lg border border-neutral-200 text-sm" placeholder="6 м">
            </div>
            <div>
              <label class="block text-xs font-medium text-neutral-600 mb-1">Высота подъема</label>
              <input type="text" name="spec_lift_height" class="w-full px-3 py-2 rounded-lg border border-neutral-200 text-sm" placeholder="1100-1600 мм">
            </div>
            <div>
              <label class="block text-xs font-medium text-neutral-600 mb-1">Рабочая ширина рампы</label>
              <input type="text" name="spec_width" class="w-full px-3 py-2 rounded-lg border border-neutral-200 text-sm" placeholder="2000/2400 мм">
            </div>
            <div>
              <label class="block text-xs font-medium text-neutral-600 mb-1">Транспортировочные колеса</label>
              <input type="text" name="spec_wheels" class="w-full px-3 py-2 rounded-lg border border-neutral-200 text-sm" placeholder="пневматические R-15">
            </div>
            <div>
              <label class="block text-xs font-medium text-neutral-600 mb-1">Подъемное устройство</label>
              <input type="text" name="spec_lift_device" class="w-full px-3 py-2 rounded-lg border border-neutral-200 text-sm" placeholder="Модульная опора">
            </div>
          </div>
          <div class="mt-3">
            <label class="block text-xs font-medium text-neutral-600 mb-1">Дополнительные характеристики</label>
            <div id="extra-specs" class="space-y-2"></div>
            <button type="button" onclick="addExtraSpec()" class="mt-2 text-sm text-blue-600 hover:text-blue-700">
              <i class="fas fa-plus mr-1"></i> Добавить характеристику
            </button>
          </div>
          <input type="hidden" name="specifications" id="specifications-json">
        </div>

        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
          <label class="flex items-center gap-3 p-4 bg-neutral-50 rounded-xl cursor-pointer">
            <input type="checkbox" name="in_stock" class="w-5 h-5 rounded border-neutral-300 text-blue-600 focus:ring-blue-500">
            <span class="text-sm font-medium text-neutral-700">В наличии</span>
          </label>
          <label class="flex items-center gap-3 p-4 bg-neutral-50 rounded-xl cursor-pointer">
            <input type="checkbox" name="is_hit" class="w-5 h-5 rounded border-neutral-300 text-blue-600 focus:ring-blue-500">
            <span class="text-sm font-medium text-neutral-700">Хит</span>
          </label>
          <label class="flex items-center gap-3 p-4 bg-neutral-50 rounded-xl cursor-pointer">
            <input type="checkbox" name="is_new" class="w-5 h-5 rounded border-neutral-300 text-blue-600 focus:ring-blue-500">
            <span class="text-sm font-medium text-neutral-700">Новинка</span>
          </label>
          <label class="flex items-center gap-3 p-4 bg-neutral-50 rounded-xl cursor-pointer">
            <input type="checkbox" name="is_active" class="w-5 h-5 rounded border-neutral-300 text-blue-600 focus:ring-blue-500" checked>
            <span class="text-sm font-medium text-neutral-700">Активен</span>
          </label>
        </div>

        <div class="border-t border-neutral-100 pt-6">
          <h4 class="text-sm font-semibold text-neutral-700 mb-4">SEO настройки</h4>
          <div class="space-y-4">
            <div>
              <label class="block text-sm font-medium text-neutral-700 mb-2">SEO Title</label>
              <input type="text" name="seo_title" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200">
            </div>
            <div>
              <label class="block text-sm font-medium text-neutral-700 mb-2">SEO Description</label>
              <textarea name="seo_description" rows="2" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200"></textarea>
            </div>
            <div>
              <label class="block text-sm font-medium text-neutral-700 mb-2">SEO Keywords</label>
              <input type="text" name="seo_keywords" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-200">
            </div>
          </div>
        </div>

        <div class="flex gap-4 pt-4">
          <button type="submit" class="flex-1 px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-xl transition-colors">
            <i class="fas fa-save mr-2"></i> Сохранить товар
          </button>
          <button type="button" onclick="closeProductModal()" class="px-6 py-3 border border-neutral-200 text-neutral-600 font-medium rounded-xl hover:bg-neutral-50 transition-colors">
            Отмена
          </button>
        </div>
      </form>
    </div>
  </div>

  <!-- Category Modal -->
  <div id="categoryModal" class="modal fixed inset-0 bg-black/50 z-50 items-center justify-center p-4">
    <div class="bg-white rounded-2xl max-w-lg w-full">
      <div class="p-6 border-b border-neutral-100 flex justify-between items-center">
        <h3 id="categoryModalTitle" class="text-xl font-bold text-neutral-800">Добавить категорию</h3>
        <button onclick="closeCategoryModal()" class="w-10 h-10 rounded-xl hover:bg-neutral-100 transition-colors">
          <i class="fas fa-times text-neutral-500"></i>
        </button>
      </div>
      <form id="categoryForm" class="p-6 space-y-4">
        <input type="hidden" name="id" id="categoryId">
        <div>
          <label class="block text-sm font-medium text-neutral-700 mb-2">Название *</label>
          <input type="text" name="name" required class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500">
        </div>
        <div>
          <label class="block text-sm font-medium text-neutral-700 mb-2">Slug *</label>
          <input type="text" name="slug" required class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500">
        </div>
        <div>
          <label class="block text-sm font-medium text-neutral-700 mb-2">Описание</label>
          <textarea name="description" rows="3" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500"></textarea>
        </div>
        <div>
          <label class="block text-sm font-medium text-neutral-700 mb-2">Порядок сортировки</label>
          <input type="number" name="sort_order" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500" value="0">
        </div>
        <label class="flex items-center gap-3">
          <input type="checkbox" name="is_active" class="w-5 h-5 rounded border-neutral-300 text-blue-600" checked>
          <span class="text-sm font-medium text-neutral-700">Активна</span>
        </label>
        <div class="flex gap-4 pt-4">
          <button type="submit" class="flex-1 px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-xl">Сохранить</button>
          <button type="button" onclick="closeCategoryModal()" class="px-6 py-3 border border-neutral-200 text-neutral-600 rounded-xl hover:bg-neutral-50">Отмена</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Case Modal -->
  <div id="caseModal" class="modal fixed inset-0 bg-black/50 z-50 items-center justify-center p-4">
    <div class="bg-white rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
      <div class="p-6 border-b border-neutral-100 flex justify-between items-center sticky top-0 bg-white">
        <h3 id="caseModalTitle" class="text-xl font-bold text-neutral-800">Добавить кейс</h3>
        <button onclick="closeCaseModal()" class="w-10 h-10 rounded-xl hover:bg-neutral-100"><i class="fas fa-times text-neutral-500"></i></button>
      </div>
      <form id="caseForm" class="p-6 space-y-4">
        <input type="hidden" name="id" id="caseId">
        <div>
          <label class="block text-sm font-medium text-neutral-700 mb-2">Название проекта *</label>
          <input type="text" name="title" required class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500">
        </div>
        <div>
          <label class="block text-sm font-medium text-neutral-700 mb-2">Описание</label>
          <textarea name="description" rows="3" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500"></textarea>
        </div>
        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="block text-sm font-medium text-neutral-700 mb-2">Клиент</label>
            <input type="text" name="client_name" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500">
          </div>
          <div>
            <label class="block text-sm font-medium text-neutral-700 mb-2">Локация</label>
            <input type="text" name="location" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500">
          </div>
        </div>
        <div>
          <label class="block text-sm font-medium text-neutral-700 mb-2">Результат</label>
          <textarea name="result_text" rows="2" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500"></textarea>
        </div>
        <div>
          <label class="block text-sm font-medium text-neutral-700 mb-2">Главное изображение (URL)</label>
          <input type="text" name="main_image" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500" placeholder="https://...">
          <p class="text-xs text-neutral-500 mt-1">Вставьте URL или загрузите изображение</p>
          <input type="file" accept="image/*" onchange="uploadImage(this, 'caseForm', 'main_image')" class="mt-2 text-sm">
        </div>
        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="block text-sm font-medium text-neutral-700 mb-2">Порядок</label>
            <input type="number" name="sort_order" class="w-full px-4 py-3 rounded-xl border border-neutral-200" value="0">
          </div>
          <label class="flex items-center gap-3 self-end pb-3">
            <input type="checkbox" name="is_active" class="w-5 h-5 rounded border-neutral-300 text-blue-600" checked>
            <span class="text-sm font-medium text-neutral-700">Активен</span>
          </label>
        </div>
        <div class="flex gap-4 pt-4">
          <button type="submit" class="flex-1 px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-xl">Сохранить</button>
          <button type="button" onclick="closeCaseModal()" class="px-6 py-3 border border-neutral-200 text-neutral-600 rounded-xl hover:bg-neutral-50">Отмена</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Partner Modal -->
  <div id="partnerModal" class="modal fixed inset-0 bg-black/50 z-50 items-center justify-center p-4">
    <div class="bg-white rounded-2xl max-w-lg w-full">
      <div class="p-6 border-b border-neutral-100 flex justify-between items-center">
        <h3 id="partnerModalTitle" class="text-xl font-bold text-neutral-800">Добавить партнёра</h3>
        <button onclick="closePartnerModal()" class="w-10 h-10 rounded-xl hover:bg-neutral-100"><i class="fas fa-times text-neutral-500"></i></button>
      </div>
      <form id="partnerForm" class="p-6 space-y-4">
        <input type="hidden" name="id" id="partnerId">
        <div>
          <label class="block text-sm font-medium text-neutral-700 mb-2">Название компании *</label>
          <input type="text" name="name" required class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500">
        </div>
        <div>
          <label class="block text-sm font-medium text-neutral-700 mb-2">URL логотипа</label>
          <input type="text" name="logo_url" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500" placeholder="https://...">
          <input type="file" accept="image/*" onchange="uploadImage(this, 'partnerForm', 'logo_url')" class="mt-2 text-sm">
        </div>
        <div>
          <label class="block text-sm font-medium text-neutral-700 mb-2">Сайт</label>
          <input type="url" name="website_url" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500" placeholder="https://company.ru">
        </div>
        <div>
          <label class="block text-sm font-medium text-neutral-700 mb-2">Описание</label>
          <textarea name="description" rows="2" class="w-full px-4 py-3 rounded-xl border border-neutral-200 focus:border-blue-500"></textarea>
        </div>
        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="block text-sm font-medium text-neutral-700 mb-2">Порядок</label>
            <input type="number" name="sort_order" class="w-full px-4 py-3 rounded-xl border border-neutral-200" value="0">
          </div>
          <label class="flex items-center gap-3 self-end pb-3">
            <input type="checkbox" name="is_active" class="w-5 h-5 rounded border-neutral-300 text-blue-600" checked>
            <span class="text-sm font-medium text-neutral-700">Активен</span>
          </label>
        </div>
        <div class="flex gap-4 pt-4">
          <button type="submit" class="flex-1 px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-xl">Сохранить</button>
          <button type="button" onclick="closePartnerModal()" class="px-6 py-3 border border-neutral-200 text-neutral-600 rounded-xl hover:bg-neutral-50">Отмена</button>
        </div>
      </form>
    </div>
  </div>

  <script>
    // Init admin name
    const adminUser = JSON.parse(localStorage.getItem('adminUser') || '{}');
    document.getElementById('admin-name').textContent = adminUser.username || 'Администратор';

    function logout() {
      localStorage.removeItem('adminToken');
      localStorage.removeItem('adminUser');
      window.location.href = '/admin/login';
    }
    
    function showSection(section) {
      document.querySelectorAll('.admin-section').forEach(el => el.classList.add('hidden'));
      document.getElementById('section-' + section).classList.remove('hidden');
      
      document.querySelectorAll('.nav-link').forEach(a => {
        a.classList.remove('bg-blue-50', 'text-blue-600', 'font-medium');
        a.classList.add('text-neutral-600');
      });
      event.target.closest('a').classList.add('bg-blue-50', 'text-blue-600', 'font-medium');
      event.target.closest('a').classList.remove('text-neutral-600');
      
      if (section === 'categories') loadCategories();
    }

    function showSettingsTab(tab) {
      document.querySelectorAll('.settings-tab').forEach(el => el.classList.add('hidden'));
      document.getElementById('settings-' + tab).classList.remove('hidden');
      
      document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active', 'bg-blue-600', 'text-white');
        btn.classList.add('bg-neutral-100', 'text-neutral-600');
      });
      event.target.classList.add('active');
      event.target.classList.remove('bg-neutral-100', 'text-neutral-600');
    }

    // Dashboard
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
          const recentLeads = (leads.data || []).slice(0, 5);
          document.getElementById('recent-leads').innerHTML = recentLeads.length ? recentLeads.map(lead => 
            '<div class="flex justify-between items-center p-4 bg-neutral-50 rounded-xl">' +
              '<div><p class="font-medium text-neutral-800">' + lead.name + '</p>' +
              '<p class="text-sm text-neutral-500">' + lead.phone + '</p></div>' +
              '<span class="px-3 py-1 rounded-full text-xs font-medium ' + 
              (lead.status === 'new' ? 'bg-orange-100 text-orange-600' : lead.status === 'processing' ? 'bg-blue-100 text-blue-600' : 'bg-green-100 text-green-600') + '">' + 
              (lead.status === 'new' ? 'Новая' : lead.status === 'processing' ? 'В работе' : 'Завершена') + '</span></div>'
          ).join('') : '<p class="text-neutral-500 text-center py-4">Заявок пока нет</p>';
        }
      } catch (e) {
        console.error('Error loading dashboard:', e);
      }
    }

    // Products
    async function loadProducts() {
      const response = await fetch('/api/admin/products');
      const data = await response.json();
      
      document.getElementById('products-table').innerHTML = (data.data || []).map(product => 
        '<tr class="hover:bg-neutral-50">' +
          '<td class="px-6 py-4"><img src="' + (product.main_image || 'https://via.placeholder.com/60x60?text=No+image') + '" class="w-14 h-14 object-cover rounded-lg"></td>' +
          '<td class="px-6 py-4"><div class="font-medium text-neutral-800">' + product.name + '</div><div class="text-sm text-neutral-500">' + product.slug + '</div></td>' +
          '<td class="px-6 py-4 text-neutral-600">' + (product.category_name || '-') + '</td>' +
          '<td class="px-6 py-4 font-semibold">' + (product.price ? product.price.toLocaleString('ru-RU') + ' ₽' : '-') + '</td>' +
          '<td class="px-6 py-4"><span class="px-3 py-1 rounded-full text-xs font-medium ' + (product.is_active ? 'bg-green-100 text-green-600' : 'bg-neutral-100 text-neutral-500') + '">' + (product.is_active ? 'Активен' : 'Скрыт') + '</span></td>' +
          '<td class="px-6 py-4"><div class="flex gap-2">' +
            '<button onclick="editProduct(' + product.id + ')" class="w-9 h-9 rounded-lg bg-blue-50 hover:bg-blue-100 text-blue-600 transition-colors"><i class="fas fa-edit"></i></button>' +
            '<button onclick="deleteProduct(' + product.id + ')" class="w-9 h-9 rounded-lg bg-red-50 hover:bg-red-100 text-red-600 transition-colors"><i class="fas fa-trash"></i></button>' +
          '</div></td></tr>'
      ).join('') || '<tr><td colspan="6" class="px-6 py-8 text-center text-neutral-500">Товаров нет</td></tr>';
    }

    // Categories
    async function loadCategories() {
      const response = await fetch('/api/categories');
      const data = await response.json();
      
      document.getElementById('categories-table').innerHTML = (data.data || []).map(cat => 
        '<tr class="hover:bg-neutral-50">' +
          '<td class="px-6 py-4 font-medium text-neutral-800">' + cat.name + '</td>' +
          '<td class="px-6 py-4 text-neutral-500">' + cat.slug + '</td>' +
          '<td class="px-6 py-4">' + (cat.sort_order || 0) + '</td>' +
          '<td class="px-6 py-4"><span class="px-3 py-1 rounded-full text-xs font-medium ' + (cat.is_active ? 'bg-green-100 text-green-600' : 'bg-neutral-100 text-neutral-500') + '">' + (cat.is_active ? 'Активна' : 'Скрыта') + '</span></td>' +
          '<td class="px-6 py-4"><div class="flex gap-2">' +
            '<button onclick="editCategory(' + cat.id + ')" class="w-9 h-9 rounded-lg bg-blue-50 hover:bg-blue-100 text-blue-600 transition-colors"><i class="fas fa-edit"></i></button>' +
            '<button onclick="deleteCategory(' + cat.id + ')" class="w-9 h-9 rounded-lg bg-red-50 hover:bg-red-100 text-red-600 transition-colors"><i class="fas fa-trash"></i></button>' +
          '</div></td></tr>'
      ).join('') || '<tr><td colspan="5" class="px-6 py-8 text-center text-neutral-500">Категорий нет</td></tr>';
    }

    // Leads
    async function loadLeads() {
      const response = await fetch('/api/admin/leads');
      const data = await response.json();
      
      document.getElementById('leads-table').innerHTML = (data.data || []).map(lead => 
        '<tr class="hover:bg-neutral-50">' +
          '<td class="px-6 py-4 text-sm text-neutral-500">' + new Date(lead.created_at).toLocaleString('ru-RU') + '</td>' +
          '<td class="px-6 py-4 font-medium text-neutral-800">' + lead.name + '</td>' +
          '<td class="px-6 py-4"><a href="tel:' + lead.phone + '" class="text-blue-600 hover:underline">' + lead.phone + '</a></td>' +
          '<td class="px-6 py-4">' + (lead.email || '-') + '</td>' +
          '<td class="px-6 py-4 text-sm text-neutral-500 max-w-xs truncate">' + (lead.message || '-') + '</td>' +
          '<td class="px-6 py-4"><select onchange="updateLeadStatus(' + lead.id + ', this.value)" class="px-3 py-2 rounded-lg border border-neutral-200 text-sm focus:border-blue-500">' +
            '<option value="new"' + (lead.status === 'new' ? ' selected' : '') + '>Новая</option>' +
            '<option value="processing"' + (lead.status === 'processing' ? ' selected' : '') + '>В работе</option>' +
            '<option value="completed"' + (lead.status === 'completed' ? ' selected' : '') + '>Завершена</option>' +
          '</select></td>' +
          '<td class="px-6 py-4"><div class="flex gap-2">' +
            '<a href="tel:' + lead.phone + '" class="w-9 h-9 rounded-lg bg-green-50 hover:bg-green-100 text-green-600 flex items-center justify-center transition-colors"><i class="fas fa-phone"></i></a>' +
            (lead.email ? '<a href="mailto:' + lead.email + '" class="w-9 h-9 rounded-lg bg-blue-50 hover:bg-blue-100 text-blue-600 flex items-center justify-center transition-colors"><i class="fas fa-envelope"></i></a>' : '') +
          '</div></td></tr>'
      ).join('') || '<tr><td colspan="7" class="px-6 py-8 text-center text-neutral-500">Заявок нет</td></tr>';
    }

    async function updateLeadStatus(id, status) {
      await fetch('/api/admin/leads/' + id, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status })
      });
      loadDashboard();
    }

    // Settings
    async function loadSettings() {
      const response = await fetch('/api/settings');
      const data = await response.json();
      const settings = data.data || {};
      
      const form = document.getElementById('settings-form');
      Object.keys(settings).forEach(key => {
        const input = form.querySelector('[name="' + key + '"]');
        if (input) {
          if (input.type === 'checkbox') {
            input.checked = settings[key] === '1' || settings[key] === 'true';
          } else {
            input.value = settings[key];
          }
        }
      });
    }

    document.getElementById('settings-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(e.target);
      const settings = {};
      formData.forEach((value, key) => {
        settings[key] = value;
      });
      
      const response = await fetch('/api/admin/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings)
      });
      
      if (response.ok) {
        alert('Настройки успешно сохранены!');
      } else {
        alert('Ошибка сохранения настроек');
      }
    });

    // Product Modal
    function openProductModal(product = null) {
      const modal = document.getElementById('productModal');
      const form = document.getElementById('productForm');
      const title = document.getElementById('productModalTitle');
      const select = document.getElementById('productCategorySelect');
      
      // Populate categories
      select.innerHTML = '<option value="">Выберите категорию</option>' + 
        categories.map(c => '<option value="' + c.id + '">' + c.name + '</option>').join('');
      
      form.reset();
      document.getElementById('productId').value = '';
      
      // Clear extra specs
      document.getElementById('extra-specs').innerHTML = '';
      
      if (product) {
        title.textContent = 'Редактировать товар';
        document.getElementById('productId').value = product.id;
        form.name.value = product.name || '';
        form.slug.value = product.slug || '';
        form.category_id.value = product.category_id || '';
        form.price.value = product.price || '';
        form.old_price.value = product.old_price || '';
        form.sort_order.value = product.sort_order || 0;
        form.short_description.value = product.short_description || '';
        form.full_description.value = product.full_description || '';
        form.main_image.value = product.main_image || '';
        form.images.value = (product.images ? (typeof product.images === 'string' ? JSON.parse(product.images) : product.images) : []).join('\\n');
        
        // Parse specifications into form fields
        let specs = {};
        try {
          specs = product.specifications ? (typeof product.specifications === 'string' ? JSON.parse(product.specifications) : product.specifications) : {};
        } catch(e) { specs = {}; }
        
        // Fill standard spec fields
        form.spec_length.value = specs['Общая длина'] || '';
        form.spec_capacity.value = specs['Грузоподъемность'] || '';
        form.spec_platform_length.value = specs['Длина площадки'] || '';
        form.spec_lift_length.value = specs['Длина подъема'] || '';
        form.spec_lift_height.value = specs['Высота подъема'] || '';
        form.spec_width.value = specs['Рабочая ширина рампы'] || '';
        form.spec_wheels.value = specs['Транспортировочные колеса'] || '';
        form.spec_lift_device.value = specs['Подъемное устройство'] || '';
        
        // Add extra specs
        const standardKeys = ['Общая длина', 'Грузоподъемность', 'Длина площадки', 'Длина подъема', 'Высота подъема', 'Рабочая ширина рампы', 'Транспортировочные колеса', 'Подъемное устройство'];
        Object.keys(specs).forEach(key => {
          if (!standardKeys.includes(key) && specs[key]) {
            addExtraSpec(key, specs[key]);
          }
        });
        
        form.in_stock.checked = !!product.in_stock;
        form.is_hit.checked = !!product.is_hit;
        form.is_new.checked = !!product.is_new;
        form.is_active.checked = !!product.is_active;
        form.seo_title.value = product.seo_title || '';
        form.seo_description.value = product.seo_description || '';
        form.seo_keywords.value = product.seo_keywords || '';
      } else {
        title.textContent = 'Добавить товар';
        form.is_active.checked = true;
        form.in_stock.checked = true;
        // Clear spec fields
        form.spec_length.value = '';
        form.spec_capacity.value = '';
        form.spec_platform_length.value = '';
        form.spec_lift_length.value = '';
        form.spec_lift_height.value = '';
        form.spec_width.value = '';
        form.spec_wheels.value = '';
        form.spec_lift_device.value = '';
      }
      
      modal.classList.add('active');
    }

    function closeProductModal() {
      document.getElementById('productModal').classList.remove('active');
    }

    async function editProduct(id) {
      const response = await fetch('/api/admin/products');
      const data = await response.json();
      const product = data.data.find(p => p.id === id);
      if (product) openProductModal(product);
    }

    async function deleteProduct(id) {
      if (!confirm('Удалить этот товар?')) return;
      await fetch('/api/admin/products/' + id, { method: 'DELETE' });
      loadProducts();
      loadDashboard();
    }

    // Add extra specification field
    function addExtraSpec(key = '', value = '') {
      const container = document.getElementById('extra-specs');
      const idx = container.children.length;
      const div = document.createElement('div');
      div.className = 'flex gap-2';
      div.innerHTML = \`
        <input type="text" name="extra_spec_key_\${idx}" value="\${key}" class="flex-1 px-3 py-2 rounded-lg border border-neutral-200 text-sm" placeholder="Название">
        <input type="text" name="extra_spec_val_\${idx}" value="\${value}" class="flex-1 px-3 py-2 rounded-lg border border-neutral-200 text-sm" placeholder="Значение">
        <button type="button" onclick="this.parentElement.remove()" class="px-3 py-2 text-red-500 hover:bg-red-50 rounded-lg"><i class="fas fa-times"></i></button>
      \`;
      container.appendChild(div);
    }
    
    // Collect specifications from form
    function collectSpecifications(form) {
      const specs = {};
      
      // Standard fields
      if (form.spec_length.value) specs['Общая длина'] = form.spec_length.value;
      if (form.spec_capacity.value) specs['Грузоподъемность'] = form.spec_capacity.value;
      if (form.spec_platform_length.value) specs['Длина площадки'] = form.spec_platform_length.value;
      if (form.spec_lift_length.value) specs['Длина подъема'] = form.spec_lift_length.value;
      if (form.spec_lift_height.value) specs['Высота подъема'] = form.spec_lift_height.value;
      if (form.spec_width.value) specs['Рабочая ширина рампы'] = form.spec_width.value;
      if (form.spec_wheels.value) specs['Транспортировочные колеса'] = form.spec_wheels.value;
      if (form.spec_lift_device.value) specs['Подъемное устройство'] = form.spec_lift_device.value;
      
      // Extra fields
      let i = 0;
      while (form['extra_spec_key_' + i]) {
        const key = form['extra_spec_key_' + i].value.trim();
        const val = form['extra_spec_val_' + i].value.trim();
        if (key && val) specs[key] = val;
        i++;
      }
      
      return specs;
    }

    document.getElementById('productForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = e.target;
      const id = document.getElementById('productId').value;
      
      let images = [];
      try {
        images = form.images.value.split('\\n').filter(url => url.trim());
      } catch (e) {}
      
      const specifications = collectSpecifications(form);
      
      const data = {
        name: form.name.value,
        slug: form.slug.value,
        category_id: parseInt(form.category_id.value),
        price: parseInt(form.price.value),
        old_price: form.old_price.value ? parseInt(form.old_price.value) : null,
        sort_order: parseInt(form.sort_order.value) || 0,
        short_description: form.short_description.value,
        full_description: form.full_description.value,
        main_image: form.main_image.value,
        images: images,
        specifications: specifications,
        in_stock: form.in_stock.checked,
        is_hit: form.is_hit.checked,
        is_new: form.is_new.checked,
        is_active: form.is_active.checked,
        seo_title: form.seo_title.value,
        seo_description: form.seo_description.value,
        seo_keywords: form.seo_keywords.value
      };
      
      const url = id ? '/api/admin/products/' + id : '/api/admin/products';
      const method = id ? 'PUT' : 'POST';
      
      const response = await fetch(url, {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      
      if (response.ok) {
        closeProductModal();
        loadProducts();
        loadDashboard();
        alert(id ? 'Товар обновлен!' : 'Товар добавлен!');
      } else {
        const err = await response.json();
        alert('Ошибка: ' + (err.error || 'Неизвестная ошибка'));
      }
    });

    // Image preview
    document.querySelector('[name="main_image"]').addEventListener('input', function() {
      const preview = document.getElementById('mainImagePreview');
      if (this.value) {
        preview.querySelector('img').src = this.value;
        preview.classList.remove('hidden');
      } else {
        preview.classList.add('hidden');
      }
    });

    // Category Modal
    function openCategoryModal(category = null) {
      const modal = document.getElementById('categoryModal');
      const form = document.getElementById('categoryForm');
      const title = document.getElementById('categoryModalTitle');
      
      form.reset();
      document.getElementById('categoryId').value = '';
      
      if (category) {
        title.textContent = 'Редактировать категорию';
        document.getElementById('categoryId').value = category.id;
        form.name.value = category.name || '';
        form.slug.value = category.slug || '';
        form.description.value = category.description || '';
        form.sort_order.value = category.sort_order || 0;
        form.is_active.checked = !!category.is_active;
      } else {
        title.textContent = 'Добавить категорию';
        form.is_active.checked = true;
      }
      
      modal.classList.add('active');
    }

    function closeCategoryModal() {
      document.getElementById('categoryModal').classList.remove('active');
    }

    async function editCategory(id) {
      const response = await fetch('/api/categories');
      const data = await response.json();
      const category = data.data.find(c => c.id === id);
      if (category) openCategoryModal(category);
    }

    async function deleteCategory(id) {
      if (!confirm('Удалить эту категорию?')) return;
      await fetch('/api/admin/categories/' + id, { method: 'DELETE' });
      loadCategories();
    }

    document.getElementById('categoryForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = e.target;
      const id = document.getElementById('categoryId').value;
      
      const data = {
        name: form.name.value,
        slug: form.slug.value,
        description: form.description.value,
        sort_order: parseInt(form.sort_order.value) || 0,
        is_active: form.is_active.checked
      };
      
      const url = id ? '/api/admin/categories/' + id : '/api/admin/categories';
      const method = id ? 'PUT' : 'POST';
      
      const response = await fetch(url, {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      
      if (response.ok) {
        closeCategoryModal();
        loadCategories();
        alert(id ? 'Категория обновлена!' : 'Категория добавлена!');
        // Reload page to update categories in product form
        location.reload();
      } else {
        const err = await response.json();
        alert('Ошибка: ' + (err.error || 'Неизвестная ошибка'));
      }
    });

    // ===== Cases CRUD =====
    async function loadCases() {
      const response = await fetch('/api/admin/cases');
      const data = await response.json();
      
      document.getElementById('cases-table').innerHTML = (data.data || []).map(item => 
        '<tr class="hover:bg-neutral-50">' +
          '<td class="px-6 py-4"><img src="' + (item.main_image || 'https://via.placeholder.com/60x60?text=No+image') + '" class="w-14 h-14 object-cover rounded-lg"></td>' +
          '<td class="px-6 py-4"><div class="font-medium text-neutral-800">' + item.title + '</div></td>' +
          '<td class="px-6 py-4 text-neutral-600">' + (item.client_name || '-') + '</td>' +
          '<td class="px-6 py-4 text-neutral-500">' + (item.location || '-') + '</td>' +
          '<td class="px-6 py-4"><span class="px-3 py-1 rounded-full text-xs font-medium ' + (item.is_active ? 'bg-green-100 text-green-600' : 'bg-neutral-100 text-neutral-500') + '">' + (item.is_active ? 'Активен' : 'Скрыт') + '</span></td>' +
          '<td class="px-6 py-4"><div class="flex gap-2">' +
            '<button onclick="editCase(' + item.id + ')" class="w-9 h-9 rounded-lg bg-blue-50 hover:bg-blue-100 text-blue-600"><i class="fas fa-edit"></i></button>' +
            '<button onclick="deleteCase(' + item.id + ')" class="w-9 h-9 rounded-lg bg-red-50 hover:bg-red-100 text-red-600"><i class="fas fa-trash"></i></button>' +
          '</div></td></tr>'
      ).join('') || '<tr><td colspan="6" class="px-6 py-8 text-center text-neutral-500">Кейсов нет</td></tr>';
    }

    function openCaseModal(caseItem = null) {
      const modal = document.getElementById('caseModal');
      const form = document.getElementById('caseForm');
      const title = document.getElementById('caseModalTitle');
      
      form.reset();
      document.getElementById('caseId').value = '';
      
      if (caseItem) {
        title.textContent = 'Редактировать кейс';
        document.getElementById('caseId').value = caseItem.id;
        form.title.value = caseItem.title || '';
        form.description.value = caseItem.description || '';
        form.client_name.value = caseItem.client_name || '';
        form.location.value = caseItem.location || '';
        form.result_text.value = caseItem.result_text || '';
        form.main_image.value = caseItem.main_image || '';
        form.sort_order.value = caseItem.sort_order || 0;
        form.is_active.checked = !!caseItem.is_active;
      } else {
        title.textContent = 'Добавить кейс';
        form.is_active.checked = true;
      }
      
      modal.classList.add('active');
    }

    function closeCaseModal() {
      document.getElementById('caseModal').classList.remove('active');
    }

    async function editCase(id) {
      const response = await fetch('/api/admin/cases');
      const data = await response.json();
      const item = data.data.find(c => c.id === id);
      if (item) openCaseModal(item);
    }

    async function deleteCase(id) {
      if (!confirm('Удалить этот кейс?')) return;
      await fetch('/api/admin/cases/' + id, { method: 'DELETE' });
      loadCases();
    }

    document.getElementById('caseForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = e.target;
      const id = document.getElementById('caseId').value;
      
      const data = {
        title: form.title.value,
        description: form.description.value,
        client_name: form.client_name.value,
        location: form.location.value,
        result_text: form.result_text.value,
        main_image: form.main_image.value,
        sort_order: parseInt(form.sort_order.value) || 0,
        is_active: form.is_active.checked
      };
      
      const url = id ? '/api/admin/cases/' + id : '/api/admin/cases';
      const method = id ? 'PUT' : 'POST';
      
      const response = await fetch(url, {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      
      if (response.ok) {
        closeCaseModal();
        loadCases();
        alert(id ? 'Кейс обновлен!' : 'Кейс добавлен!');
      } else {
        const err = await response.json();
        alert('Ошибка: ' + (err.error || 'Неизвестная ошибка'));
      }
    });

    // ===== Partners CRUD =====
    async function loadPartners() {
      const response = await fetch('/api/admin/partners');
      const data = await response.json();
      
      document.getElementById('partners-table').innerHTML = (data.data || []).map(item => 
        '<tr class="hover:bg-neutral-50">' +
          '<td class="px-6 py-4">' + (item.logo_url ? '<img src="' + item.logo_url + '" class="h-10 w-auto object-contain">' : '<span class="text-neutral-400">-</span>') + '</td>' +
          '<td class="px-6 py-4 font-medium text-neutral-800">' + item.name + '</td>' +
          '<td class="px-6 py-4">' + (item.website_url ? '<a href="' + item.website_url + '" target="_blank" class="text-blue-600 hover:underline">' + item.website_url + '</a>' : '-') + '</td>' +
          '<td class="px-6 py-4">' + (item.sort_order || 0) + '</td>' +
          '<td class="px-6 py-4"><span class="px-3 py-1 rounded-full text-xs font-medium ' + (item.is_active ? 'bg-green-100 text-green-600' : 'bg-neutral-100 text-neutral-500') + '">' + (item.is_active ? 'Активен' : 'Скрыт') + '</span></td>' +
          '<td class="px-6 py-4"><div class="flex gap-2">' +
            '<button onclick="editPartner(' + item.id + ')" class="w-9 h-9 rounded-lg bg-blue-50 hover:bg-blue-100 text-blue-600"><i class="fas fa-edit"></i></button>' +
            '<button onclick="deletePartner(' + item.id + ')" class="w-9 h-9 rounded-lg bg-red-50 hover:bg-red-100 text-red-600"><i class="fas fa-trash"></i></button>' +
          '</div></td></tr>'
      ).join('') || '<tr><td colspan="6" class="px-6 py-8 text-center text-neutral-500">Партнёров нет</td></tr>';
    }

    function openPartnerModal(partner = null) {
      const modal = document.getElementById('partnerModal');
      const form = document.getElementById('partnerForm');
      const title = document.getElementById('partnerModalTitle');
      
      form.reset();
      document.getElementById('partnerId').value = '';
      
      if (partner) {
        title.textContent = 'Редактировать партнёра';
        document.getElementById('partnerId').value = partner.id;
        form.name.value = partner.name || '';
        form.logo_url.value = partner.logo_url || '';
        form.website_url.value = partner.website_url || '';
        form.description.value = partner.description || '';
        form.sort_order.value = partner.sort_order || 0;
        form.is_active.checked = !!partner.is_active;
      } else {
        title.textContent = 'Добавить партнёра';
        form.is_active.checked = true;
      }
      
      modal.classList.add('active');
    }

    function closePartnerModal() {
      document.getElementById('partnerModal').classList.remove('active');
    }

    async function editPartner(id) {
      const response = await fetch('/api/admin/partners');
      const data = await response.json();
      const item = data.data.find(p => p.id === id);
      if (item) openPartnerModal(item);
    }

    async function deletePartner(id) {
      if (!confirm('Удалить этого партнёра?')) return;
      await fetch('/api/admin/partners/' + id, { method: 'DELETE' });
      loadPartners();
    }

    document.getElementById('partnerForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = e.target;
      const id = document.getElementById('partnerId').value;
      
      const data = {
        name: form.name.value,
        logo_url: form.logo_url.value,
        website_url: form.website_url.value,
        description: form.description.value,
        sort_order: parseInt(form.sort_order.value) || 0,
        is_active: form.is_active.checked
      };
      
      const url = id ? '/api/admin/partners/' + id : '/api/admin/partners';
      const method = id ? 'PUT' : 'POST';
      
      const response = await fetch(url, {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      
      if (response.ok) {
        closePartnerModal();
        loadPartners();
        alert(id ? 'Партнёр обновлен!' : 'Партнёр добавлен!');
      } else {
        const err = await response.json();
        alert('Ошибка: ' + (err.error || 'Неизвестная ошибка'));
      }
    });

    // ===== Image Upload =====
    async function uploadImage(input, formId, fieldName) {
      const file = input.files[0];
      if (!file) return;
      
      const formData = new FormData();
      formData.append('file', file);
      
      try {
        const response = await fetch('/api/admin/upload', {
          method: 'POST',
          body: formData
        });
        
        const data = await response.json();
        if (data.success && data.url) {
          document.querySelector('#' + formId + ' [name="' + fieldName + '"]').value = data.url;
          // Update preview if exists
          const previewEl = document.getElementById(fieldName === 'main_image' ? 'mainImagePreview' : fieldName + '_preview');
          if (previewEl) {
            const img = previewEl.querySelector('img');
            if (img) img.src = data.url;
            previewEl.classList.remove('hidden');
          }
          alert('Изображение загружено!');
        } else {
          alert('Ошибка загрузки: ' + (data.error || 'Неизвестная ошибка'));
        }
      } catch (e) {
        alert('Ошибка загрузки изображения');
      }
    }

    // Settings image upload
    async function uploadSettingsImage(input, fieldName) {
      const file = input.files[0];
      if (!file) return;
      
      const formData = new FormData();
      formData.append('file', file);
      
      try {
        const response = await fetch('/api/admin/upload', {
          method: 'POST',
          body: formData
        });
        
        const data = await response.json();
        if (data.success && data.url) {
          document.querySelector('[name="' + fieldName + '"]').value = data.url;
          // Update preview
          const previewEl = document.getElementById(fieldName + '_preview');
          if (previewEl) {
            const img = previewEl.querySelector('img');
            if (img) img.src = data.url;
            previewEl.classList.remove('hidden');
          }
          alert('Изображение загружено!');
        } else {
          alert('Ошибка загрузки: ' + (data.error || 'Неизвестная ошибка'));
        }
      } catch (e) {
        alert('Ошибка загрузки изображения');
      }
    }

    // Init
    loadDashboard();
    loadProducts();
    loadLeads();
    loadSettings();
    
    // Load cases and partners when those sections are shown
    const origShowSection = showSection;
    showSection = function(section) {
      if (section === 'cases') loadCases();
      if (section === 'partners') loadPartners();
      if (section === 'categories') loadCategories();
      
      document.querySelectorAll('.admin-section').forEach(el => el.classList.add('hidden'));
      document.getElementById('section-' + section).classList.remove('hidden');
      
      document.querySelectorAll('.nav-link').forEach(a => {
        a.classList.remove('bg-blue-50', 'text-blue-600', 'font-medium');
        a.classList.add('text-neutral-600');
      });
      if (event && event.target) {
        const link = event.target.closest('a');
        if (link) {
          link.classList.add('bg-blue-50', 'text-blue-600', 'font-medium');
          link.classList.remove('text-neutral-600');
        }
      }
    };
  </script>
</body>
</html>`)
})

export default app
