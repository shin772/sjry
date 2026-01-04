require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const xss = require('xss');
const path = require('path');
const mysql = require('mysql2/promise');

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'Hospital_Secure_Key_025';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// MySQL 连接池配置
const pool = mysql.createPool({
  host: process.env.MYSQL_HOST || 'mysql',
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD || '',
  database: process.env.MYSQL_DATABASE || 'mysql',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelayMs: 0,
  authPlugins: {
    mysql_native_password: () => () => ''
  }
});

let dbConnected = false;

// 数据库初始化 - 带重试机制
async function initDB() {
  let retries = 5;
  while (retries > 0) {
    try {
      const connection = await pool.getConnection();
      await connection.query(`
        CREATE TABLE IF NOT EXISTS feedbacks (
          id INT AUTO_INCREMENT PRIMARY KEY,
          type VARCHAR(50),
          department VARCHAR(100),
          target_role VARCHAR(100),
          target_name VARCHAR(100),
          description TEXT,
          submitter_name VARCHAR(100),
          submitter_phone VARCHAR(50),
          ip_address VARCHAR(50),
          status VARCHAR(20) DEFAULT 'pending',
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
      connection.release();
      dbConnected = true;
      console.log('✅ MySQL 数据库连接成功');
      return;
    } catch (error) {
      retries--;
      console.error(`⚠️ MySQL 连接失败 (重试 ${5 - retries}/5):`, error.message);
      if (retries > 0) {
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }
  }
  dbConnected = false;
  console.error('❌ MySQL 连接失败，应用将以离线模式运行');
}

// 异步初始化，不阻塞应用启动
initDB();

// 中间件
app.use(helmet());
app.use((req, res, next) => {
res.setHeader(
  'Content-Security-Policy',
  "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://unpkg.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net blob:; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; font-src 'self' data: https://cdnjs.cloudflare.com; img-src 'self' data: https:;"
);
  next();
});
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// 限流设置
const submitLimiter = rateLimit({ 
  windowMs: 10 * 60 * 1000, 
  max: 10, 
  message: { success: false, message: "操作过于频繁，请稍后再试" },
  skip: (req) => {
    return req.ip === '127.0.0.1' || req.ip === '::1';
  },
  keyGenerator: (req) => {
    return req.headers['x-forwarded-for'] || req.ip;
  }
});

// 提交反馈
app.post('/api/submit', submitLimiter, async (req, res) => {
  if (!dbConnected) {
    return res.status(503).json({ success: false, message: "数据库暂时不可用，请稍后重试" });
  }

  let { 
    type, department, targetRole, targetName, 
    description, submitterName, submitterPhone 
  } = req.body;

  // 数据验证 - 修复：联系方式字段现在是可选的
  if (!type || !department || !description) {
    return res.status(400).json({ success: false, message: "缺少必要字段" });
  }

  targetRole = xss(targetRole || '');
  targetName = xss(targetName || '');
  description = xss(description);
  submitterName = xss(submitterName || '');
  submitterPhone = xss(submitterPhone || '');

  const ipAddress = req.ip || req.connection.remoteAddress;

  try {
    const connection = await pool.getConnection();
    const [result] = await connection.query(
      `INSERT INTO feedbacks (type, department, target_role, target_name, description, submitter_name, submitter_phone, ip_address) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [type, department, targetRole, targetName, description, submitterName, submitterPhone, ipAddress]
    );
    connection.release();
    
    console.log(`✅ 反馈提交成功，ID: ${result.insertId}`);
    res.json({ success: true, message: "提交成功", id: result.insertId });
  } catch (error) {
    console.error('❌ 提交失败:', error.message);
    res.status(500).json({ success: false, message: "提交失败: " + error.message });
  }
});

// 管理员登录
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  
  if (password === ADMIN_PASSWORD) {
    const token = jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token });
  } else {
    res.status(401).json({ success: false, message: "密码错误" });
  }
});

// 获取反馈列表
app.get('/api/admin/list', async (req, res) => {
  if (!dbConnected) {
    return res.status(503).json({ success: false, message: "数据库暂时不可用" });
  }

  const token = req.headers.authorization?.split(' ')[1];
  
  try {
    jwt.verify(token, JWT_SECRET);
    const connection = await pool.getConnection();
    const [rows] = await connection.query('SELECT * FROM feedbacks ORDER BY created_at DESC');
    connection.release();
    res.json(rows);
  } catch (error) {
    res.status(401).json({ success: false, message: "认证失败" });
  }
});

// 删除反馈
app.delete('/api/admin/delete/:id', async (req, res) => {
  if (!dbConnected) {
    return res.status(503).json({ success: false, message: "数据库暂时不可用" });
  }

  const token = req.headers.authorization?.split(' ')[1];
  
  try {
    jwt.verify(token, JWT_SECRET);
    const connection = await pool.getConnection();
    await connection.query('DELETE FROM feedbacks WHERE id = ?', [req.params.id]);
    connection.release();
    res.json({ success: true, message: "删除成功" });
  } catch (error) {
    res.status(401).json({ success: false, message: "认证失败" });
  }
});

// 测试数据库连接
app.get('/api/test-db', async (req, res) => {
  if (!dbConnected) {
    return res.status(503).json({ 
      success: false, 
      message: "数据库连接失败",
      status: "OFFLINE"
    });
  }

  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.query('SELECT COUNT(*) as count FROM feedbacks');
    connection.release();
    res.json({ 
      success: true, 
      message: "数据库连接正常", 
      count: rows[0].count,
      database: "MySQL",
      status: "ONLINE"
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message, status: "ERROR" });
  }
});

// 健康检查端点
app.get('/api/health', (req, res) => {
  res.json({ 
    status: "OK",
    database: dbConnected ? "CONNECTED" : "DISCONNECTED",
    timestamp: new Date().toISOString()
  });
});

// 静态文件路由 - 修复：指向 public 文件夹中的文件
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/admin.html'));
});

// 启动服务器
app.listen(PORT, () => {
  console.log(`🚀 服务器运行在 ${PORT} 端口`);
  console.log(`📱 前端访问: http://localhost:${PORT}`);
  console.log(`🔐 管理员访问: http://localhost:${PORT}/admin`);
  console.log(`🧪 测试数据库: http://localhost:${PORT}/api/test-db`);
  console.log(`❤️ 健康检查: http://localhost:${PORT}/api/health`);
});
