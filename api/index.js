import Fastify from "fastify";
import jwt from "@fastify/jwt";
import bcrypt from "bcryptjs";
import { PrismaClient } from "./generated/prisma/index.js";
import { z } from "zod";

const prisma = new PrismaClient();
const fastify = Fastify({ logger: false });

await fastify.register(jwt, { secret: "super-secret" });

fastify.decorate("authenticate", async function (request, reply) {
  try {
    await request.jwtVerify();
  } catch (err) {
    return reply.code(401).send("Unauthorized");
  }
});

function validateSchema(schema) {
  return async function (req, reply) {
    if (!req.body) {
      return reply.code(400).send({ error: "Request body is required" });
    }

    const result = schema.safeParse(req.body);
    if (!result.success) {
      return reply.code(400).send(result.error.flatten());
    }
    req.body = result.data; // Override with parsed data
  };
}

// Schemas
const usernameSchema = z
  .string()
  .min(3, "Username must be between 3 and 32 characters")
  .max(32, 'Username must be between 3 and 32 characters')
  .regex(/^[a-zA-Z0-9_]+$/, "Username can only contain letters, numbers, and underscores");
const passwordSchema = z
  .string()
  .min(6, "Password must be between 6 and 32 characters")
  .max(32, "Password must be between 6 and 32 characters")
  .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{6,32}$/, 'Password must contain at least one uppercase letter, one lowercase letter, and one number');
const emailSchema = z.string().min(5, "Email must be at least 5 characters long").max(128, "Email must be at most 128 characters long").email("Invalid email format");

const registerSchema = z.object({
  username: usernameSchema,
  email: emailSchema,
  password: passwordSchema,
});

const signinSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
});

const changePasswordSchema = z.object({
  newPassword: passwordSchema,
  oldPassword: passwordSchema,
});

const forgetPasswordSchema = z.object({
  email: emailSchema,
  newPassword: passwordSchema,
});

// Routes

fastify.get("/", async (req, reply) => {
  const users = await prisma.user.findMany({
    select: { id: true, username: true, email: true },
  });
  reply.send(users);
});

fastify.post(
  "/register",
  { preHandler: [validateSchema(registerSchema)] },
  async (req, reply) => {
    const { username, email, password } = req.body;

    const exists = await prisma.user.findUnique({ where: { email } });
    if (exists) {
      return reply.code(409).send("Email already registered");
    }

    const hash = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: { username, email, password: hash },
    });

    reply
      .code(201)
      .send({ id: user.id, username: user.username, email: user.email });
  }
);

fastify.post(
  "/signin",
  { preHandler: [validateSchema(signinSchema)] },
  async (req, reply) => {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return reply.code(401).send("Invalid credentials");
    }

    const token = fastify.jwt.sign({ id: user.id, email: user.email });
    reply.send({ token });
  }
);

fastify.patch(
  "/change-password",
  { preHandler: [fastify.authenticate, validateSchema(changePasswordSchema)] },
  async (req, reply) => {
    const { oldPassword, newPassword } = req.body;
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });

    if (!user || !(await bcrypt.compare(oldPassword, user.password))) {
      return reply.code(400).send("Old password incorrect");
    }

    const newHash = await bcrypt.hash(newPassword, 10);
    await prisma.user.update({
      where: { id: user.id },
      data: { password: newHash },
    });

    reply.code(204).send(); // No content
  }
);

fastify.post(
  "/forget-password",
  { preHandler: [validateSchema(forgetPasswordSchema)] },
  async (req, reply) => {
    const { email, newPassword } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return reply.code(404).send("User not found");
    }

    const newHash = await bcrypt.hash(newPassword, 10);
    await prisma.user.update({
      where: { id: user.id },
      data: { password: newHash },
    });

    reply.send("Password reset successful");
  }
);

// Start server
fastify.listen({ port: 3000 }, (err) => {
  if (err) throw err;
  console.log("Server running on port 3000");
});
